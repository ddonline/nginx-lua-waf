#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <lua.h>
#include <lauxlib.h>
static int getmicrosecond(lua_State *L) {
    struct timeval tv;
    gettimeofday(&tv,NULL);
    long microsecond = tv.tv_sec*1000000+tv.tv_usec;
    lua_pushnumber(L, microsecond);
    return 1;
}
static int getmillisecond(lua_State *L) {
    struct timeval tv;
    gettimeofday(&tv,NULL);
    long millisecond = (tv.tv_sec*1000000+tv.tv_usec)/1000;
    lua_pushnumber(L, millisecond);
    
    return 1;
}
static const struct luaL_Reg myLib[] =   
    {  
    {"getmillisecond", getmillisecond},
    {"getmicrosecond", getmicrosecond},
    { NULL, NULL }
    };


int luaopen_usertime(lua_State *L) {
  luaL_register(L, "FPCalc", myLib); 
  return 1;
}
