:- style_check(-singleton).

user_input_might_reach_method(Fqn) :-
    strrchr(Fqn, MethodName),
    kb_has_fqn(Call, FqnTag),
    kb_call(Call),
    string_concat(_, MethodName, FqnTag).

strrchr(String, Value) :-
    sub_string(String, Before, Length, 0, Value),
    sub_string(String, BeforeTag, LengthTag, 0, ValueTag),
    string_concat('.', Value, ValueTag),
    succ(Length, LengthTag),
    succ(BeforeTag, Before),
    sub_string(String, _, 1, _, '.'),
    \+ sub_string(Value, _, 1, _, '.').

utils_endswith(Haystack, Needle) :-
    sub_string(Haystack, _, _, 0, Needle).

user_input_might_reach_function_suffixed_by(Pqn) :-
    utils_user_input_might_reach_function_whose_pqn_is(Pqn).

utils_user_input_might_reach_function_whose_pqn_is(Pqn) :-
    utils_user_input_might_reach_callable_whose_fqn_is(Fqn),
    utils_endswith(Fqn, Pqn).

utils_user_input_might_reach_callable_whose_fqn_is(Fqn) :-
    utils_user_input_might_reach_function_whose_fqn_is(Fqn).   

user_input_might_reach_function(Fqn) :-
    utils_user_input_might_reach_function_whose_fqn_is(Fqn).

utils_user_input_might_reach_function_whose_fqn_is(Fqn) :-
    kb_has_fqn(Call, Fqn),
    utils_concrete_user_input_might_reach_function_call(_, Call).

utils_concrete_user_input_might_reach_function_call(UserInput, Call) :-
    utils_user_input(UserInput),
    kb_call(Call),
    utils_dataflow_path(UserInput, Call),
    kb_arg_for_call(Arg, Call).

% This is for cases like Ruby's SomeClass.method.call
% it is not labeled as a call, since at the syntactic level
% it's just an expression ( fixed while working on CVE-2024-33667 )
utils_concrete_user_input_might_reach_function_call(UserInput, Call) :-
    utils_user_input(UserInput),
    utils_dataflow_path(UserInput, Call).

utils_user_input(UserInput) :- utils_user_input_originated_from_npm_express_post_request_params(UserInput).
utils_user_input(UserInput) :- utils_user_input_originated_from_composer_laravel_post_request_params(UserInput).
utils_user_input(UserInput) :- utils_user_input_originated_from_pip_gradio_button_click_dispatch(UserInput).
utils_user_input(UserInput) :- utils_user_input_originated_from_ruby_rails_post_request_params(UserInput).
utils_user_input(UserInput) :- utils_user_input_originated_from_pip_fastapi_get_request_params(UserInput).
% add more web frameworks here ...

utils_user_input_originated_from_pip_fastapi_get_request_params(UserInput) :-
    kb_callable(Callable),
    kb_callable_annotated_with(Calleble, 'fastapi.APIRouter.get'),
    kb_callable_has_param(Callable, UserInput).

utils_user_input_originated_from_composer_laravel_post_request_params(UserInput) :-
    utils_composer_laravel_post_handler(Call),
    kb_arg_for_call(Callback, Call),
    kb_callable(Callback),
    kb_callable_has_param(Callback, UserInput),
    kb_param_has_name(UserInput, 'request').

utils_user_input_originated_from_npm_express_post_request_params(UserInput) :-
    utils_npm_express_post_handler(Call),
    kb_arg_for_call(Callback, Call),
    kb_callable(Callback),
    kb_callable_has_param(Callback, UserInput),
    kb_param_has_name(UserInput, 'req').

utils_user_input_originated_from_pip_gradio_button_click_dispatch(UserInput) :-
    utils_pip_gradio_button_click(Call),
    kb_arg_for_call(Callback, Call),
    kb_callable(Callback),
    kb_callable_has_param(Callback, UserInput).

utils_user_input_originated_from_ruby_rails_post_request_params(UserInput) :-
    utils_ruby_rails_class_controller(Class),
    kb_method_of_class(_, Class), % <--- Method ...
    %kb_variable_inside_method(UserInput, Method),
    kb_has_fqn(UserInput, 'params').

utils_ruby_rails_class_controller(Class) :-
    kb_class_name(Class, Name),
    utils_ends_with(Name, 'Controller').

utils_ends_with(Haystack, Needle) :-
    sub_atom(Haystack, _, _, _, Needle). 

utils_composer_laravel_post_handler(Call) :-
    kb_call(Call),
    kb_has_fqn(Call, 'composer.Illuminate.Support.Facades.Route.post').

utils_npm_express_post_handler(Call) :-
    kb_call(Call),
    kb_has_fqn(Call, 'npm.express.post').

utils_pip_gradio_button_click(Call) :-
    kb_call(Call),
    kb_has_fqn(Call, 'gradio.Button.click').

utils_dataflow_edge(U, V) :- kb_dataflow_edge(U, V).
utils_dataflow_edge(Arg, Param) :-
    kb_arg_for_call(Arg, Call),
    kb_has_fqn(Call, Fqn),
    kb_has_fqn(Callable, Fqn),
    kb_callable_has_param(Callable, Param).

% until the abstract interpretation is working ...
utils_dataflow_path(U, V) :-
    utils_dataflow_edge(U,V).
utils_dataflow_path(U, V) :-
    utils_dataflow_edge(U,W),
    utils_dataflow_edge(W,V).
utils_dataflow_path(U, V) :-
    utils_dataflow_edge(U,W),
    utils_dataflow_edge(W,X),
    utils_dataflow_edge(X,V).
utils_dataflow_path(U, V) :-
    utils_dataflow_edge(U,W),
    utils_dataflow_edge(W,X),
    utils_dataflow_edge(X,Y),
    utils_dataflow_edge(Y,V).
utils_dataflow_path(U, V) :-
    utils_dataflow_edge(U,W),
    utils_dataflow_edge(W,X),
    utils_dataflow_edge(X,Y),
    utils_dataflow_edge(Y,Z),
    utils_dataflow_edge(Z,V).
utils_dataflow_path(U, V) :-
    utils_dataflow_edge(U,W),
    utils_dataflow_edge(W,X),
    utils_dataflow_edge(X,Y),
    utils_dataflow_edge(Y,Z),
    utils_dataflow_edge(Z,T),
    utils_dataflow_edge(T,V).
utils_dataflow_path(U, V) :-
    utils_dataflow_edge(U,W),
    utils_dataflow_edge(W,X),
    utils_dataflow_edge(X,Y),
    utils_dataflow_edge(Y,Z),
    utils_dataflow_edge(Z,T),
    utils_dataflow_edge(T,M),
    utils_dataflow_edge(M,V).
