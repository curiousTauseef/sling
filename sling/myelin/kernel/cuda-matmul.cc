// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "sling/myelin/kernel/cuda.h"

#include <string>

#include "sling/myelin/cuda/cuda-kernel.h"

namespace sling {
namespace myelin {

// Matrix multiplication using CUDA.
class CUDAMatMulBase : public CUDAKernel {
 public:
  // Maximum number of loop unrolls.
  static const int MAX_UNROLLS = 8;

  CUDAMatMulBase(bool bias, bool relu) : bias_(bias), relu_(relu) {}

  bool Supports(Step *step) override {
    // Requires CUDA support.
    if (!CUDAKernel::Supports(step)) return false;

    // Two or three 2D tensor inputs and one 2D tensor output.
    if (step->inputs().size() != (bias_ ? 3 : 2)) return false;
    if (step->outputs().size() != 1) return false;
    Tensor *A = step->input(0);
    Tensor *B = step->input(1);
    Tensor *C = step->output(0);
    if (A->rank() != 2 || B->rank() != 2 || C->rank() != 2) return false;

    // Check shape.
    if (A->dim(0) != C->dim(0)) return false;
    if (A->dim(1) != B->dim(0)) return false;
    if (B->dim(1) != C->dim(1)) return false;

    // Types must match and be supported by CUDA.
    Type type = A->type();
    if (TypeTraits::of(type).ptx() == nullptr) return false;
    if (B->type() != type || C->type() != type) return false;

    // Check bias vector.
    if (bias_) {
      Tensor *v = step->input(2);
      if (v->type() != type) return false;
      if (v->rank() == 1) {
        if (v->dim(0) != C->dim(1)) return false;
      } else if (v->rank() == 2) {
        if (v->dim(0) != 1 || v->dim(1) != C->dim(1)) return false;
      } else {
        return false;
      }
    }

    // Transpose not supported.
    if (step->GetAttr("transpose_a", false)) return false;
    if (step->GetAttr("transpose_b", false)) return false;
    if (step->GetAttr("transpose_c", false)) return false;

    return true;
  }

  void Adjust(Step *step) override {
    // Prefer row-major.
    Tensor *A = step->input(0);
    Tensor *B = step->input(1);
    Tensor *C = step->output(0);
    A->RequireOrder(ROW_MAJOR_PREFERRED);
    B->RequireOrder(ROW_MAJOR_PREFERRED);
    C->RequireOrder(ROW_MAJOR_PREFERRED);
  }

  void GeneratePTX(Step *step, PTXMacroAssembler *ptx) override {
    // Get input and output tensors.
    Tensor *A = step->input(0);
    Tensor *B = step->input(1);
    Tensor *v = bias_ ? step->input(2) : nullptr;
    Tensor *C = step->output(0);

    int width = C->dim(1);
    int height = C->dim(0);
    int depth = A->dim(1);

    Type dtype = A->type();
    const TypeTraits &traits = TypeTraits::of(dtype);
    const char *type = traits.ptx();
    bool fp = dtype == DT_FLOAT || dtype == DT_DOUBLE || dtype == DT_HALF;
    bool vec = height == 1;
    int dsize = traits.size();

    // Compute number of unrolls.
    int unrolls = 0;
    for (int i = 1; i <= MAX_UNROLLS; ++i) {
      if (depth % i == 0) unrolls = i;
    }
    if (step->variant().empty()) {
      string variant = "U" + std::to_string(unrolls);
      step->set_variant(variant);
    }

    // Set grid size. Use one thread for each output element in C.
    ptx->set_grid_dims(width, height);

    // Get output row and column in C.
    ptx_decl(u32, col);
    ptx->LoadThreadIndex(col, 0);
    ptx_decl(u32, row);
    if (!vec) {
      ptx->LoadThreadIndex(row, 1);
    }

    // Check bounds.
    if (vec) {
      ptx_decl(pred, outside);
      ptx_emit(setp.ge.u32, outside, col, PTXImm(width));
      ptx_if(outside);
      ptx_jump(done);
      ptx_endif();
    } else {
      ptx_decl(pred, outside_col);
      ptx_emit(setp.ge.u32, outside_col, col, PTXImm(width));
      ptx_decl(pred, outside_row);
      ptx_emit(setp.ge.u32, outside_row, row, PTXImm(height));
      ptx_decl(pred, outside);
      ptx_emit(or.pred, outside, outside_col, outside_row);
      ptx_if(outside);
      ptx_jump(done);
      ptx_endif();
    }

    // Compute address of row in A.
    ptx_decl(b64, aptr);
    ptx->LoadTensorAddress(aptr, A);
    if (!vec) {
      ptx_emit(mad.wide.u32, aptr, row, PTXImm(A->stride(0)), aptr);
    }

    // Compute address of column in B.
    ptx_decl(b64, bptr);
    ptx->LoadTensorAddress(bptr, B);
    ptx_emit(mad.wide.u32, bptr, col, PTXImm(B->stride(1)), bptr);

    // Compute dot product.
    PTXConst zero(PTXConst::ZERO, type);
    ptx_decl(u32, idx);
    ptx_emit(mov.u32, idx, PTXImm(0));
    PTXReg sum = ptx->reg(type, "sum");
    ptx->emit(PTXInstr("mov", type), sum, zero);
    ptx_label(loop);

    // Compute sum += A[row,idx] * B[idx,col].
    PTXReg a = ptx->reg(type, "a");
    PTXReg b = ptx->reg(type, "b");
    for (int i = 0; i < unrolls; ++i) {
      int aofs = i * A->stride(1);
      int bofs = i * B->stride(0);
      ptx->emit(PTXInstr("ld.global", type), a, PTXAddr(aptr, aofs));
      ptx->emit(PTXInstr("ld.global", type), b, PTXAddr(bptr, bofs));
      ptx->emit(PTXInstr(fp ? "fma.rn" : "mad.lo", type), sum, a, b, sum);
    }

    // Next element.
    if (unrolls != depth) {
      ptx_emit(add.u32, idx, idx, PTXImm(unrolls));
      ptx_emit(add.u64, aptr, aptr, PTXImm(A->stride(1) * unrolls));
      ptx_emit(add.u64, bptr, bptr, PTXImm(B->stride(0) * unrolls));

      ptx_decl(pred, more);
      ptx_emit(setp.lt.u32, more, idx, PTXImm(depth));
      ptx_if(more);
      ptx_jump(loop);
      ptx_endif();
    }

    // Optionally add bias.
    if (bias_) {
      ptx_decl(b64, vptr);
      ptx->LoadTensorAddress(vptr, v);
      ptx_emit(mad.wide.u32, vptr, col, PTXImm(dsize), vptr);

      PTXReg bias = ptx->reg(type, "bias");
      ptx->emit(PTXInstr("ld.global", type), bias, PTXAddr(vptr));
      ptx->emit(PTXInstr("add", type), sum, sum, bias);
    }

    // Optionally compute relu.
    if (relu_) {
      ptx->emit(PTXInstr("max", type), sum, sum, zero);
    }

    // Save result in C[row,col].
    ptx_decl(b64, cptr);
    ptx->LoadTensorAddress(cptr, C);
    if (!vec) {
      ptx_emit(mad.wide.u32, cptr, row, PTXImm(C->stride(0)), cptr);
    }
    ptx_emit(mad.wide.u32, cptr, col, PTXImm(C->stride(1)), cptr);
    ptx->emit(PTXInstr("st.global", type), PTXAddr(cptr), sum);

    // Done.
    ptx_label(done);
    ptx_ret();
  }

  int64 Complexity(const Step *step) override {
    int64 ops = step->input(0)->dim(0);
    ops *= step->input(1)->elements() * 2;
    if (bias_) ops += step->input(2)->elements();
    if (relu_) ops += step->output(0)->elements();
    return ops;
  }

 protected:
  bool bias_;    // add bias vector to result, y=Wx+b
  bool relu_;    // apply rectified linear unit, y=max(0,Wx+b)
};

class CUDAMatMul : public CUDAMatMulBase {
 public:
  CUDAMatMul() : CUDAMatMulBase(false, false) {}

  string Name() override { return "CUDAMatMul"; }
  string Operation() override { return "MatMul"; }
};

class CUDAMatMulAdd : public CUDAMatMulBase {
 public:
  CUDAMatMulAdd() : CUDAMatMulBase(true, false) {}

  string Name() override { return "CUDAMatMulAdd"; }
  string Operation() override { return "MatMulAdd"; }
};

class CUDAMatMulRelu : public CUDAMatMulBase {
 public:
  CUDAMatMulRelu() : CUDAMatMulBase(false, true) {}

  string Name() override { return "CUDAMatMulRelu"; }
  string Operation() override { return "MatMulRelu"; }
};

class CUDAMatMulAddRelu : public CUDAMatMulBase {
 public:
  CUDAMatMulAddRelu() : CUDAMatMulBase(true, true) {}

  string Name() override { return "CUDAMatMulAddRelu"; }
  string Operation() override { return "MatMulAddRelu"; }
};

// Tiled matrix multiplication using CUDA.
class CUDAMatMulTiled : public CUDAKernel {
 public:
  // Tile block size.
  static const int TILE_SIZE = 16;

  string Name() override { return "CUDAMatMulTiled"; }
  string Operation() override { return "MatMul"; }

  bool Supports(Step *step) override {
    // Requires CUDA support.
    if (!CUDAKernel::Supports(step)) return false;

    // Two 2D tensor inputs and one 2D tensor output.
    if (step->inputs().size() != 2) return false;
    if (step->outputs().size() != 1) return false;
    Tensor *A = step->input(0);
    Tensor *B = step->input(1);
    Tensor *C = step->output(0);
    if (A->rank() != 2 || B->rank() != 2 || C->rank() != 2) return false;

    // Check shape.
    if (A->dim(0) != C->dim(0)) return false;
    if (A->dim(1) != B->dim(0)) return false;
    if (B->dim(1) != C->dim(1)) return false;

    // Types must match and be supported by CUDA.
    Type type = A->type();
    if (TypeTraits::of(type).ptx() == nullptr) return false;
    if (B->type() != type || C->type() != type) return false;

    // Check that matrices can be tiled.
    if (A->dim(0) % TILE_SIZE != 0) return false;
    if (A->dim(1) % TILE_SIZE != 0) return false;
    if (B->dim(1) % TILE_SIZE != 0) return false;

    // Transpose not supported.
    if (step->GetAttr("transpose_a", false)) return false;
    if (step->GetAttr("transpose_b", false)) return false;
    if (step->GetAttr("transpose_c", false)) return false;

    return true;
  }

  void Adjust(Step *step) override {
    // Prefer row-major.
    Tensor *A = step->input(0);
    Tensor *B = step->input(1);
    Tensor *C = step->output(0);
    A->RequireOrder(ROW_MAJOR_PREFERRED);
    B->RequireOrder(ROW_MAJOR_PREFERRED);
    C->RequireOrder(ROW_MAJOR_PREFERRED);
  }

  void GeneratePTX(Step *step, PTXMacroAssembler *ptx) override {
    // Get input and output tensors.
    Tensor *A = step->input(0);
    Tensor *B = step->input(1);
    Tensor *C = step->output(0);

    int width = C->dim(1);
    int height = C->dim(0);
    int depth = A->dim(1);

    Type dtype = A->type();
    const TypeTraits &traits = TypeTraits::of(dtype);
    const char *type = traits.ptx();
    bool fp = dtype == DT_FLOAT || dtype == DT_DOUBLE || dtype == DT_HALF;
    int dsize = traits.size();

    // Set the block size to the title size and use one tread per output
    // element.
    ptx->set_block_dims(TILE_SIZE, TILE_SIZE);
    ptx->set_grid_dims(width, height);

    // Declare shared memory for tiles of A and B.
    char str[128];
    sprintf(str, ".shared .f32 ablock[%d];\n", TILE_SIZE * TILE_SIZE);
    ptx->emit(str);
    sprintf(str, ".shared .f32 bblock[%d];\n", TILE_SIZE * TILE_SIZE);
    ptx->emit(str);
    ptx_decl(b64, atile);
    ptx_decl(b64, btile);
    ptx_emit(mov.u64, atile, PTXLiteral("ablock"));
    ptx_emit(mov.u64, btile, PTXLiteral("bblock"));

    // Get block x and y indicies.
    ptx_decl(u32, bx);
    ptx_decl(u32, by);
    ptx->LoadBlockIndex(bx, 0);
    ptx->LoadBlockIndex(by, 1);

    // Get tile x and y indices.
    ptx_decl(u32, tx);
    ptx_decl(u32, ty);
    ptx->LoadBlockThreadIndex(tx, 0);
    ptx->LoadBlockThreadIndex(ty, 1);

    // Compute output row and column.
    ptx_decl(u32, x);
    ptx_decl(u32, y);
    ptx_emit(mad.lo.u32, x, bx, PTXImm(TILE_SIZE), tx);
    ptx_emit(mad.lo.u32, y, by, PTXImm(TILE_SIZE), ty);

    // Compute address of first A tile row.
    ptx_decl(b64, aptr);
    ptx->LoadTensorAddress(aptr, A);
    ptx_emit(mad.wide.u32, aptr, y, PTXImm(A->stride(0)), aptr);
    ptx_emit(mad.wide.u32, aptr, tx, PTXImm(A->stride(1)), aptr);

    // Compute address of first B tile column.
    ptx_decl(b64, bptr);
    ptx->LoadTensorAddress(bptr, B);
    ptx_emit(mad.wide.u32, bptr, ty, PTXImm(B->stride(0)), bptr);
    ptx_emit(mad.wide.u32, bptr, x, PTXImm(B->stride(1)), bptr);

    // Compute offset of (col,row) element in tiles. These are pointers to
    // the elements in the shared memory blocks that the thread is responsible
    // for loading.
    ptx_decl(b64, ain);
    ptx_emit(mad.wide.u32, ain, ty, PTXImm(dsize * TILE_SIZE), atile);
    ptx_emit(mad.wide.u32, ain, tx, PTXImm(dsize), ain);

    ptx_decl(b64, bin);
    ptx_emit(mad.wide.u32, bin, ty, PTXImm(dsize * TILE_SIZE), btile);
    ptx_emit(mad.wide.u32, bin, tx, PTXImm(dsize), bin);

    // Sub-matrices of A and B that thread is summing over.
    ptx_decl(b64, as);
    ptx_decl(b64, bs);
    ptx_emit(mad.wide.u32, as, ty, PTXImm(dsize * TILE_SIZE), atile);
    ptx_emit(mad.wide.u32, bs, tx, PTXImm(dsize), btile);

    // Accumulate result for C[row,col].
    PTXConst zero(PTXConst::ZERO, type);
    PTXReg c = ptx->reg(type, "c");
    ptx->emit(PTXInstr("mov", type), c, zero);

    // Loop over all the tiles of A and B that are required to compute the
    // tile in C.
    ptx_decl(u32, idx);
    ptx_emit(mov.u32, idx, PTXImm(0));
    ptx_label(loop);

    // Load A and B tiles from device memory to shared memory. Each thread loads
    // one element from each of the A and B tiles.
    PTXReg a = ptx->reg(type, "a");
    PTXReg b = ptx->reg(type, "b");
    ptx->emit(PTXInstr("ld.global", type), a, PTXAddr(aptr));
    ptx->emit(PTXInstr("st.shared", type), PTXAddr(ain), a);
    ptx->emit(PTXInstr("ld.global", type), b, PTXAddr(bptr));
    ptx->emit(PTXInstr("st.shared", type), PTXAddr(bin), b);

    // Synchronize to make sure the tiles are loaded before starting the
    // computation.
    ptx_emit(bar.sync, PTXImm(0));

    // Multiply A and B tiles together.
    for (int i = 0; i < TILE_SIZE; ++i) {
      // c += a[row,i] * b[i,col].
      int aofs = i * dsize;
      int bofs = i * dsize * TILE_SIZE;
      ptx->emit(PTXInstr("ld.shared", type), a, PTXAddr(as, aofs));
      ptx->emit(PTXInstr("ld.shared", type), b, PTXAddr(bs, bofs));
      ptx->emit(PTXInstr(fp ? "fma.rn" : "mad.lo", type), c, a, b, c);
    }

    // Synchronize to make sure that the preceding computation is done before
    // loading new tiles of A and B in the next iteration.
    ptx_emit(bar.sync, PTXImm(0));

    // Next tile.
    ptx_emit(add.u64, aptr, aptr, PTXImm(A->stride(1) * TILE_SIZE));
    ptx_emit(add.u64, bptr, bptr, PTXImm(B->stride(0) * TILE_SIZE));
    ptx_emit(add.u32, idx, idx, PTXImm(TILE_SIZE));

    ptx_decl(pred, more);
    ptx_emit(setp.lt.u32, more, idx, PTXImm(depth));
    ptx_if(more);
    ptx_jump(loop);
    ptx_endif();

    // Store result in C[row,col].
    ptx_decl(b64, cptr);
    ptx->LoadTensorAddress(cptr, C);
    ptx_emit(mad.wide.u32, cptr, y, PTXImm(C->stride(0)), cptr);
    ptx_emit(mad.wide.u32, cptr, x, PTXImm(C->stride(1)), cptr);
    ptx->emit(PTXInstr("st.global", type), PTXAddr(cptr), c);

    // Done.
    ptx_label(done);
    ptx_ret();
  }

  int64 Complexity(const Step *step) override {
    int64 ops = step->input(0)->dim(0);
    ops *= step->input(1)->elements() * 2;
    return ops;
  }
};

void RegisterCUDAMatMulLibrary(Library *library) {
  library->Register(new CUDAMatMul());
  library->Register(new CUDAMatMulAdd());
  library->Register(new CUDAMatMulRelu());
  library->Register(new CUDAMatMulAddRelu());
  library->Register(new CUDAMatMulTiled());
}

}  // namespace myelin
}  // namespace sling

