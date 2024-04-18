:- [ kb ].    % entire source code as prolog knowledge base
:- [ utils ]. % repetitive elements for *many* scanners

cve(_) :- user_input_might_reach_function('npm.vm2.VM.run').

main :- (cve(_) -> write('yes\n') ; write('no\n')).
