#include <ip-tree.h>

long ipt_add(ipt* t, char * key, int len, int amount)
{
  ipt * current = t;
  int i;
  for (i = 0; i < len; i++)
  {
    if (i == (len-1)) {
      ((long*)current)[key[i]] += amount;
      return ((long*)current)[key[i]];
    }
    if(!current[key[i]]) {
      current[key[i]] = create();
    }
    current = current[key[i]];
  }
}



ipt * create()
{
  ipt * n = malloc(256*sizeof(ipt));
  bzero(n,256*sizeof(ipt));
  return n;
}
