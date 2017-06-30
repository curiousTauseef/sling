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

#ifndef MYELIN_GENERATOR_INDEX_H_
#define MYELIN_GENERATOR_INDEX_H_

#include <vector>

#include "myelin/compute.h"
#include "myelin/express.h"
#include "myelin/macro-assembler.h"

namespace sling {
namespace myelin {

class IndexGenerator {
 public:
  virtual ~IndexGenerator() = default;

  // Initialize index generator.
  virtual void Initialize(size_t vecsize) = 0;

  // Allocate registers. Return false in case of register overflow.
  virtual bool AllocateRegisters(MacroAssembler *masm);

  // Return operand for accessing memory variable.
  virtual jit::Operand addr(Express::Var *var) = 0;

  // Return pointer to constant data.
  virtual void *data(Express::Var *var) = 0;

  // Return register for accessing temporary variable.
  jit::Register reg(int idx) { return regs_[idx]; }
  jit::XMMRegister xmm(int idx) {
    return jit::XMMRegister::from_code(mmregs_[idx]);
  }
  jit::YMMRegister ymm(int idx) {
    return jit::YMMRegister::from_code(mmregs_[idx]);
  }
  // Return auxiliary register.
  jit::Register aux(int idx) { return aux_[idx]; }
  jit::XMMRegister xmmaux(int idx) {
    return jit::XMMRegister::from_code(mmaux_[idx]);
  }
  jit::YMMRegister ymmaux(int idx) {
    return jit::YMMRegister::from_code(mmaux_[idx]);
  }

  // Reserve registers.
  void ReserveFixedRegister(jit::Register reg);
  void ReserveRegisters(int count);
  void ReserveAuxRegisters(int count);
  void ReserveXMMRegisters(int count);
  void ReserveAuxXMMRegisters(int count);
  void ReserveYMMRegisters(int count);
  void ReserveAuxYMMRegisters(int count);

  // Check if generator will cause register overflow.
  bool RegisterOverflow(int *usage);

 private:
  std::vector<jit::Register> fixed_;  // reserved fixed registers
  std::vector<jit::Register> regs_;   // reserved temporary registers
  std::vector<int> mmregs_;           // reserved SIMD registers (xmm/ymm)
  std::vector<jit::Register> aux_;    // reserved auxiliary registers
  std::vector<int> mmaux_;            // reserved auxiliary SIMD registers
};

}  // namespace myelin
}  // namespace sling

#endif  // MYELIN_GENERATOR_INDEX_H_

