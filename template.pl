:- [ kb ].    % entire source code as prolog knowledge base
:- [ utils ]. % repetitive elements for *many* scanners

cve(_) :- template_cve. % <--- replaced with the actual cve

main :- (cve(_) -> write('yes\n') ; write('no\n')).
