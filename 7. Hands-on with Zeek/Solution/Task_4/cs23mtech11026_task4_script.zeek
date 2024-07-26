@load base/frameworks/notice
module SSH;

export {
	const THRESHOLD: count = 5 &redef;
}

global attempts: table[addr] of count = table();

event ssh_auth_failed(c: connection) {
	local id = c$id$orig_h;
	if(id !in attempts){
            attempts[id] = 1;
	}
	else {
            attempts[id] += 1;
	}

	if (attempts[id] <= THRESHOLD) {
            print fmt ("Host: %s, Name: Bhargav, Roll No: cs23mtech11026", id);
        }

        if (attempts[id] == THRESHOLD) {
            print fmt ("Host: %s, Name: Bhargav, Roll No: cs23mtech11026, has crossed the limit (allowed attempts) to guess the password and hence declared as a brute force  attacker.", id);
	}
}


