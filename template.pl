:- style_check(-singleton).

:- discontiguous kb_class_name/2.
:- discontiguous kb_subclass_of/2.
:- discontiguous kb_const_string/2.
:- discontiguous kb_param_has_type/2.
:- discontiguous kb_param_has_name/2.
:- discontiguous kb_arg_i_for_call/3.
:- discontiguous kb_method_of_class/2.
:- discontiguous kb_param_i_of_callable/3.
:- discontiguous kb_class_has_named_super/2.
:- discontiguous kb_callable_annotated_with/2.
:- discontiguous kb_class_has_resolved_super/2.
:- discontiguous kb_callable_annotated_with_user_input_inside_route/2.

:- [ '{KNOWLEDGE_BASE}' ].
:- [ '/queryengine/utils' ].

q0(Path0) :- problems(Path0).

queries([
    q0(Path0)
]).

main :-
    queries(QueryList),
    forall(
        member(Query, QueryList),
        (Query -> (write(Query), write(': yes'), nl)); (write(Query), write(': no'), nl)
    ).
