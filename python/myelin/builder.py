# Copyright 2017 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ==============================================================================

"""Myelin function builder and expression evaluator."""

import math
from struct import pack

from flow import Variable
from flow import Function
from flow import Flow

DT_INT = "int32"
DT_FLOAT = "float32"

math_kernels = {
  'Add': lambda x, y: x + y,
  'Sub': lambda x, y: x - y,
  'Mul': lambda x, y: x * y,
  'Div': lambda x, y: x / y,
  'Minimum': lambda x, y: math.min(x, y),
  'Maximum': lambda x, y: math.max(x, y),
  'Log': math.log,
  'Exp': math.exp,
  'Tanh': math.tanh,
  'Sigmoid': lambda x: 1 / (1 + math.exp(-x)),
  'Relu': lambda x: x if x > 0 else 0,
  'Sin': math.sin,
  'Cos': math.cos,
  'Square': lambda x: x * x,
  'Reciprocal': lambda x: 1 / x,
  'Negate': lambda x: -x,
  'Abs': lambda x: math.abs(x),
}

class Builder:
  def __init__(self, flow, func):
    self.flow = flow
    self.func = flow.func(func)

  def var(self, name, dtype=DT_FLOAT, shape=[]):
    v = self.flow.var(name)
    v.type = dtype
    v.shape = shape
    return v

  def op(self, optype, args, name=None):
    if name is None: name = self.opname(optype)
    op = self.flow.op(name)
    op.type = optype
    self.func.add(op)
    for a in args:
      if not isinstance(a, Variable): a = self.const(a)
      op.add_input(a)
    dtype = op.inputs[0].type if len(op.inputs) > 0 else DT_FLOAT
    result = self.var(name + ":0", dtype)
    op.add_output(result)
    return result

  def const(self, value, dtype=None, shape=None):
    # Convert scalars.
    if type(value) is float:
      dtype = DT_FLOAT
      shape = []
      value = pack('f', value)
    elif type(value) is int:
      dtype = DT_INT
      shape = []
      value = pack('i', value)

    # Get type and shape if missing.
    if dtype is None: dtype = str(value.dtype)
    if shape is None: shape = list(value.shape)

    var = self.var(self.varname("const"), dtype, shape)
    var.data = value
    return var

  def opname(self, optype):
    name = self.func.name + '/' + optype
    if name not in self.flow.ops: return name
    index = 1
    while True:
      n = name + "_" + str(index)
      if n not in self.flow.ops: return n
      index += 1

  def varname(self, var):
    name = self.func.name + '/' + var
    if name not in self.flow.vars: return name
    index = 1
    while True:
      n = name + "_" + str(index)
      if n not in self.flow.vars: return n
      index += 1

  def add(self, x, y, name=None):
    return self.op("Add", [x, y], name)

  def sub(self, x, y, name=None):
    return self.op("Sub", [x, y], name)

  def mul(self, x, y, name=None):
    return self.op("Mul", [x, y], name)

  def div(self, x, y, name=None):
    return self.op("Div", [x, y], name)

  def min(self, x, y, name=None):
    return self.op("Minimum", [x, y], name)

  def max(self, x, y, name=None):
    return self.op("Maximum", [x, y], name)

  def matmul(self, x, y, name=None):
    return self.op("MatMul", [x, y], name)

  def log(self, x, name=None):
    return self.op("Log", [x], name)

  def exp(self, x, name=None):
    return self.op("Exp", [x], name)

  def tanh(self, x, name=None):
    return self.op("Tanh", [x], name)

  def sigmoid(self, x, name=None):
    return self.op("Sigmoid", [x], name)

  def relu(self, x, name=None):
    return self.op("Relu", [x], name)

  def sin(self, x, name=None):
    return self.op("Sin", [x], name)

  def cos(self, x, name=None):
    return self.op("Cos", [x], name)

  def square(self, x, name=None):
    return self.op("Square", [x], name)

  def negate(self, x, name=None):
    return self.op("Negate", [x], name)

  def abs(self, x, name=None):
    return self.op("Abs", [x], name)

  def reciprocal(self, x, name=None):
    return self.op("Reciprocal", [x], name)

  def ref(self, instance, var, name=None):
    r = self.op("Referece", [instance], name)
    r.producer.add_attr("var", var.name)
    r.type = var.type
    r.shape = var.shape
    return r


class Expression:
  def __init__(self, flow, func, kernels=math_kernels):
    self.flow = flow
    self.kernels = kernels
    _, self.ops = flow.order(flow.func(func))

  def evaluate(self, inputs):
    # Initialize input values
    values = {}
    for var, value in inputs.iteritems():
      if type(var) is str: var = self.flow.var(var)
      values[var] = value

    # Compute ops using kernels.
    for op in self.ops:
      # Build argument list.
      args = []
      for v in op.inputs:
        if v.data is None:
          # Variable.
          args.append(values[v])
        else:
          # Constant.
          args.append(v.data)

      # Call kernel to compute op.
      result = self.kernels[op.type](*args)
      fanout = len(op.outputs)
      if fanout == 1:
        values[op.outputs[0]] = result
      else:
        if len(result) != fanout: raise ValueError("Fanout mismatch")
        for i in xrange(fanout): values[op.outputs[i]] = result[i]

    # Return results.
    return values
