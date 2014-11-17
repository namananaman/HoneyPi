#include "ip-tree.h"

long ipt_add(ipt* t, uint8_t * key, int len, int amount, char ins)
{
  ipt * current = t;
  int i;
  for (i = 0; i < len; i++)
  {
    if (i == (len-1))
    {
      ((long*)current)[key[i]] += amount;
      return ((long*)current)[key[i]];
    }
    if((current[key[i]]==NULL) && ins)
    {
      current[key[i]] = create();
    } else if (!current[key[i]])
    {
      return -1;
    }
    current = current[key[i]];
  }
}

ipt * create()
{
  ipt * n = malloc(256*sizeof(ipt));
  memset(n,0,256*sizeof(ipt));
  //bzero(n,256*sizeof(ipt));
  return n;
}


void
ipt_iter(ipt * t, int levels, int k_len, char * k, void(f)(void*,uint8_t*,int))
{
  int i;
  for (i = 0; i < 256; i++) {
    k[(k_len - levels)] = i;
    if(t[i]!=NULL) {
      if (levels == 1) {
        f(t[i], k, k_len);
      } else {
        ipt_iter(t[i],levels-1,k_len,k,f);
      }
    }
  }
}
