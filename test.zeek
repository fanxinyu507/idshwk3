type ip_user: record{
	ip: addr;
	user: set[string];
};
global sip_usr_agent: vector of ip_user;
global cip: count = 0;

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
	if(name == "USER-AGENT")
	{
		local f1: bool = F;
		for(i in sip_usr_agent)
		{
			if(sip_usr_agent[i]$ip == c$id$orig_h)
			{
				f1 = T;
				if(value !in sip_usr_agent[i]$user)
				{
					add sip_usr_agent[i]$user[value];
				}
			}
		}
		if(f1 == F)
		{
			sip_usr_agent[cip]$ip = c$id$orig_h;
			add sip_usr_agent[cip]$user[value];
			++cip;
		}
	}
}

event zeek_done()
{
	for(i in sip_usr_agent)
	{
		if(|sip_usr_agent[i]$user| >= 3)
		{
			print fmt("%s is a proxy", sip_usr_agent[i]$ip);
		}
	}
}
