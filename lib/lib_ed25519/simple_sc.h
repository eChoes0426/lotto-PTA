#ifndef SIMPLE_SC_H
#define SIMPLE_SC_H

/*
The set of scalars is \Z/l
where l = 2^252 + 27742317777372353535851937790883648493.
*/

void sc_reduce(unsigned char *s);
void sc_muladd(unsigned char *s, const unsigned char *a, const unsigned char *b, const unsigned char *c);

#endif
