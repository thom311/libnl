%module capi
%{
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/mngt.h>
%}

%include <stdint.i>
%include <cstring.i>

