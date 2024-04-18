kb_function_call(call_startloc_32_3_endloc_32_13).
kb_function_call(call_startloc_16_1_endloc_16_8).

kb_has_npm_vm2_VM_run_fqn(call_startloc_32_3_endloc_32_13).
kb_has_npm_express_post_fqn(call_startloc_16_1_endloc_16_8).

kb_has_fqn(V, Fqn) :- kb_has_npm_vm2_VM_run_fqn(V), Fqn='npm.vm2.VM.run'.
kb_has_fqn(V, Fqn) :- kb_has_npm_express_post_fqn(V), Fqn='npm.express.post'.

kb_callable(callable_startloc_16_19_endloc_34_1).

kb_second_arg_for_call(callable_startloc_16_19_endloc_34_1, call_startloc_16_1_endloc_16_8).

kb_dataflow_path(param_startloc_16_20_endloc_16_22, argument_startloc_32_15_endloc_32_26).
kb_argument_for_call(argument_startloc_32_15_endloc_32_26, call_startloc_32_3_endloc_32_13).

kb_param(param_startloc_16_20_endloc_16_22).
kb_param_has_name(param_startloc_16_20_endloc_16_22, 'req').
kb_callable_has_param(callable_startloc_16_19_endloc_34_1, param_startloc_16_20_endloc_16_22).

