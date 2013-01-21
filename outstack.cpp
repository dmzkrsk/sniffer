#include "sniffer.h"
	
outstack::outstack(ostream* out)
{
	this->out=out;
	m_last=0;
}

int outstack::add(string& str, int n)
{
//cerr<<"+"<<n<<endl;
	m_stack[n]=str;
	int n_item=m_last;
	while(m_stack.find(n_item)!=m_stack.end())
	{
		(*out)<<(m_stack[n_item]);
		m_stack.erase(n_item);
//cerr<<"-"<<n_item<<endl;
		n_item++;
	}
	m_last=n_item;

	return n_item;
}
