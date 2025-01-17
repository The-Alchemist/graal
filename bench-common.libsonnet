{
  local common = import "common.jsonnet",
  local utils = import "common-utils.libsonnet",

  # benchmark job base with automatically generated name
  bench_base:: common.build_base + {
    # job name automatically generated: <job_prefix>-<suite>-<platform>-<jdk_version>-<os>-<arch>-<job_suffix>
    # null values are omitted from the list.
    generated_name:: utils.hyphenize([self.job_prefix, self.suite, self.platform, utils.prefixed_jdk(self.jdk_version), self.os, self.arch, self.job_suffix]),
    job_prefix:: null,
    job_suffix:: null,
    name:
      if self.is_jdk_supported(self.jdk_version) then self.generated_name
      else error "JDK" + self.jdk_version + " is not supported for " + self.generated_name + "! Suite is explicitly marked as working for JDK versions "+ self.min_jdk_version + " until " + self.max_jdk_version,
    suite:: error "'suite' must be set to generate job name",
    timelimit: error "build 'timelimit' is not set for "+ self.name +"!",
    local ol8_image = self.ci_resources.infra.ol8_bench_image,
    docker+: {
      "image": ol8_image,
      "mount_modules": true
    },
    should_use_hwloc:: std.objectHasAll(self, "is_numa") && self.is_numa && std.length(std.find("bench", self.targets)) > 0,
    min_jdk_version:: null,
    max_jdk_version:: null,
    is_jdk_supported(jdk_version)::
      if self.min_jdk_version != null && jdk_version < self.min_jdk_version then false
      else if self.max_jdk_version != null && jdk_version > self.max_jdk_version then false
      else true
  },

  bench_hw:: {
    _bench_machine:: {
      targets+: ["bench"],
      machine_name:: error "machine_name must be set!",
      local _machine_name = self.machine_name,
      capabilities+: [_machine_name],
      local GR26994_ActiveProcessorCount = "-Dnative-image.benchmark.extra-run-arg=-XX:ActiveProcessorCount="+std.toString(self.threads_per_node), # remove once GR-26994 is fixed
      environment+: { "MACHINE_NAME": _machine_name, "GR26994": GR26994_ActiveProcessorCount },
      numa_nodes:: [],
      is_numa:: std.length(self.numa_nodes) > 0,
      num_threads:: error "num_threads must bet set!",
      threads_per_node:: if self.is_numa then self.num_threads / std.length(self.numa_nodes) else self.num_threads,
    },

    x52:: common.linux + common.amd64 + self._bench_machine + {
      machine_name:: "x52",
      capabilities+: ["no_frequency_scaling", "tmpfs25g"],
      numa_nodes:: [0, 1],
      default_numa_node:: 0,
      num_threads:: 72
    },
    xgene3:: common.linux + common.aarch64 + self._bench_machine + {
      machine_name:: "xgene3",
      capabilities+: [],
      num_threads:: 32
    },
    a12c:: common.linux + common.aarch64 + self._bench_machine + {
      machine_name:: "a12c",
      capabilities+: ["no_frequency_scaling", "tmpfs25g"],
      numa_nodes:: [0, 1],
      default_numa_node:: 0,
      num_threads:: 160
    }
  },

  hwlocIfNuma(numa, cmd, node=0)::
    if numa then
      ["hwloc-bind", "--cpubind", "node:"+node, "--membind", "node:"+node, "--"] + cmd
    else
      cmd,

  parallelHwloc(cmd_node0, cmd_node1)::
    // Returns a list of commands that will run cmd_nod0 on NUMA node 0
    // concurrently with cmd_node1 on NUMA node 1 and then wait for both to complete.
    [
      $.hwlocIfNuma(true, cmd_node0, node=0) + ["&"],
      $.hwlocIfNuma(true, cmd_node1, node=1) + ["&"],
      ["wait"]
    ]
}
