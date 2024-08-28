:- style_check(-singleton).

user_input_might_reach_function(Fqn) :-
    kb_call(Call),
    kb_has_fqn(Call, Fqn),
    utils_dataflow_path(UserInput, Call),
    utils_user_input(UserInput).

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
    kb_has_fqn(UserInput, 'params'),
    utils_ruby_rails_class_controller(Class),
    kb_var_in_method(UserInput, Method),
    kb_method_of_class(Method, Class).

utils_ruby_rails_class_controller(Class) :-
    utils_subclass_of(Class, Super),
    kb_class_name(Super, 'ApplicationController' ).

utils_composer_laravel_post_handler(Call) :-
    kb_call(Call),
    kb_has_fqn(Call, 'composer.Illuminate.Support.Facades.Route.post').

utils_npm_express_post_handler(Call) :-
    kb_call(Call),
    kb_has_fqn(Call, 'npm.express.post').

utils_pip_gradio_button_click(Call) :-
    kb_call(Call),
    kb_has_fqn(Call, 'gradio.Button.click').

utils_subclass_of(Subclass, Super) :- kb_subclass_of(Subclass, Super).
utils_subclass_of(Subclass, Super) :-
    utils_subclass_of(Subclass, C),
    kb_subclass_of(C, Super).

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
utils_dataflow_path(U, V) :-
    utils_dataflow_edge(U,A),
    utils_dataflow_edge(A,B),
    utils_dataflow_edge(B,C),
    utils_dataflow_edge(C,D),
    utils_dataflow_edge(D,E),
    utils_dataflow_edge(E,F),
    utils_dataflow_edge(F,G),
    utils_dataflow_edge(G,V).
utils_dataflow_path(U, V) :-
    utils_dataflow_edge(U,A),
    utils_dataflow_edge(A,B),
    utils_dataflow_edge(B,C),
    utils_dataflow_edge(C,D),
    utils_dataflow_edge(D,E),
    utils_dataflow_edge(E,F),
    utils_dataflow_edge(F,G),
    utils_dataflow_edge(G,H),
    utils_dataflow_edge(H,V).
