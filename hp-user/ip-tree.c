#include "ip-tree.h"

long ipt_add(ipt* t, char * key, int len, int amount, char ins)
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
    if((!current[key[i]]) && ins)
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
  bzero(n,256*sizeof(ipt));
  return n;
}


ipt_iter(ipt * t, int levels)
{
  char indices[levels];
  bzero(indices,levels);
  ipt * ptrs[levels-1];
  bzero(ptrs,(levels-1)*sizeof(void*));
  while(1)
  {
    
  }
}
