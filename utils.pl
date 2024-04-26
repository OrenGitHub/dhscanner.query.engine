user_input_might_reach_function(Fqn) :-
    utils_user_input_might_reach_function_whose_fqn_is(Fqn).

utils_user_input_might_reach_function_whose_fqn_is(Fqn) :-
    kb_has_fqn(Call, Fqn),
    utils_concrete_user_input_might_reach_function_call(_, Call).

utils_concrete_user_input_might_reach_function_call(UserInput, Call) :-
    utils_user_input(UserInput),
    kb_call(Call),
    kb_dataflow_path(UserInput, Arg),
    kb_argument_for_call(Arg, Call).

utils_user_input(UserInput) :-
    utils_user_input_originated_from_express_post_request_params(UserInput).
    /* here will be a long list of all web frameworks and more ... */

utils_user_input_originated_from_express_post_request_params(UserInput) :-
    utils_express_post_handler(Call),
    kb_second_arg_for_call(Callback, Call),
    kb_callable(Callback),
    kb_callable_has_param(Callback, UserInput),
    kb_param_has_name(UserInput, 'req').

utils_express_post_handler(Call) :-
    kb_call(Call),
    kb_has_fqn(Call, 'npm.express.post').
