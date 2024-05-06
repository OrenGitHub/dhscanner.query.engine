user_input_might_reach_function(Fqn) :-
    utils_user_input_might_reach_function_whose_fqn_is(Fqn).

utils_user_input_might_reach_function_whose_fqn_is(Fqn) :-
    kb_has_fqn(Call, Fqn),
    utils_concrete_user_input_might_reach_function_call(_, Call).

utils_concrete_user_input_might_reach_function_call(UserInput, Call) :-
    utils_user_input(UserInput),
    kb_call(Call),
    utils_dataflow_path(UserInput, Arg),
    kb_arg_for_call(Arg, Call).

utils_user_input(UserInput) :- utils_user_input_originated_from_express_post_request_params(UserInput).
utils_user_input(UserInput) :- utils_user_input_originated_from_laravel_post_request_params(UserInput).
% add more web frameworks here ...

utils_user_input_originated_from_laravel_post_request_params(UserInput) :-
    utils_laravel_post_handler(Call),
    kb_arg_for_call(Callback, Call),
    kb_callable(Callback),
    kb_callable_has_param(Callback, UserInput),
    kb_param_has_name(UserInput, 'request').

utils_user_input_originated_from_express_post_request_params(UserInput) :-
    utils_express_post_handler(Call),
    kb_arg_for_call(Callback, Call),
    kb_callable(Callback),
    kb_callable_has_param(Callback, UserInput),
    kb_param_has_name(UserInput, 'req').

utils_laravel_post_handler(Call) :-
    kb_call(Call),
    kb_has_fqn(Call, 'composer.Illuminate.Support.Facades.Route.post').

utils_express_post_handler(Call) :-
    kb_call(Call),
    kb_has_fqn(Call, 'npm.express.post').

% until the abstract interpretation is working ...
utils_dataflow_path(U, V) :- kb_dataflow_edge(U,V).
utils_dataflow_path(U, V) :- kb_dataflow_edge(U,W), kb_dataflow_edge(W,V).
utils_dataflow_path(U, V) :- kb_dataflow_edge(U,W), kb_dataflow_edge(W,X), kb_dataflow_edge(X,V).
utils_dataflow_path(U, V) :- kb_dataflow_edge(U,W), kb_dataflow_edge(W,X), kb_dataflow_edge(X,Y), kb_dataflow_edge(Y,V).
utils_dataflow_path(U, V) :- kb_dataflow_edge(U,W), kb_dataflow_edge(W,X), kb_dataflow_edge(X,Y), kb_dataflow_edge(Y,Z), kb_dataflow_edge(Z,V).
utils_dataflow_path(U, V) :-
    kb_dataflow_edge(U,W),
    kb_dataflow_edge(W,X),
    kb_dataflow_edge(X,Y),
    kb_dataflow_edge(Y,Z),
    kb_dataflow_edge(Z,T),
    kb_dataflow_edge(T,V).
utils_dataflow_path(U, V) :-
    kb_dataflow_edge(U,W),
    kb_dataflow_edge(W,X),
    kb_dataflow_edge(X,Y),
    kb_dataflow_edge(Y,Z),
    kb_dataflow_edge(Z,T),
    kb_dataflow_edge(T,M),
    kb_dataflow_edge(M,V).
