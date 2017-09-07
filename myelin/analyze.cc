#include <iostream>
#include <string>

#include "base/init.h"
#include "base/flags.h"
#include "base/logging.h"
#include "base/types.h"
#include "myelin/compute.h"
#include "myelin/flow.h"
#include "myelin/graph.h"
#include "myelin/kernel/dragnn.h"
#include "myelin/kernel/tensorflow.h"

DEFINE_string(flow, "", "Myelin flow file");
DEFINE_bool(raw, false, "Do not analyze or compile flow");
DEFINE_bool(dump_flow, false, "Dump analyzed flow to stdout");
DEFINE_bool(dump_cell, false, "Dump network cell to stdout");
DEFINE_bool(tf, true, "Use Tensorflow kernel library");
DEFINE_bool(dragnn, true, "Use DRAGNN kernel library");
DEFINE_bool(check_consistency, false, "Check flow for consistency");
DEFINE_bool(profile, false, "Profile network");
DEFINE_string(cell, "", "Network cell name");
DEFINE_string(code, "", "Filename prefix for code");
DEFINE_string(graph, "", "DOT file name");

using namespace sling;
using namespace sling::myelin;

int main(int argc, char *argv[]) {
  InitProgram(&argc, &argv);

  // Set up kernel library.
  Library library;
  if (FLAGS_tf) RegisterTensorflowLibrary(&library);
  if (FLAGS_dragnn) RegisterDragnnLibrary(&library);

  // Load flow.
  Flow flow;
  LOG(INFO) << "Loading flow from " << FLAGS_flow;
  CHECK(flow.Load(FLAGS_flow));

  if (!FLAGS_raw) {
    // Analyze flow.
    LOG(INFO) << "Analyzing flow";
    flow.Analyze(library);
  }

  // Check flow consistency.
  if (FLAGS_check_consistency) {
    if (flow.IsConsistent()) {
      std::cout << "Flow is inconsistent!!!\n";
    } else {
      std::cout << "Flow is consistent\n";
    }
  }

  // Dump flow.
  if (FLAGS_dump_flow) {
    std::cout << flow.ToString();
  }

  // Output DOT graph. The file can be converted to SVG using GraphWiz dot:
  // dot /tmp/model.dot -Tsvg > model.svg
  if (!FLAGS_graph.empty()) {
    LOG(INFO) << "Writing flow graph to " << FLAGS_graph;
    GraphOptions opts;
    FlowToDotGraphFile(flow, opts, FLAGS_graph);
  }

  if (!FLAGS_raw) {
    // Compile model.
    LOG(INFO) << "Compiling flow";
    Network network;
    if (FLAGS_profile) network.set_profiling(true);
    if (!network.Compile(flow, library)) {
      std::cout << "Compilation of flow failed\n";
      return 1;
    }

    // Analyze cells.
    for (Cell *cell : network.cells()) {
      if (!FLAGS_cell.empty() && FLAGS_cell != cell->name()) continue;

      // Dump cell.
      if (FLAGS_dump_cell) {
        std::cout << cell->ToString();
      }

      // Dump generated code to file. The file can be viewed with objdump:
      // objdump -D -Mintel,x86-64 -bbinary -mi386 --no-show-raw-insn <binfn>
      if (!FLAGS_code.empty()) {
        string binfn = FLAGS_cell + cell->name() + ".bin";
        LOG(INFO) << "Writing code for " << cell->name() << " to " << binfn;
        cell->WriteCodeToFile(binfn);
      }
    }
  }

  return 0;
}

