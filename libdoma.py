# This file was automatically generated by SWIG (http://www.swig.org).
# Version 2.0.7
#
# Do not make changes to this file unless you know what you are doing--modify
# the SWIG interface file instead.



from sys import version_info
if version_info >= (2,6,0):
    def swig_import_helper():
        from os.path import dirname
        import imp
        fp = None
        try:
            fp, pathname, description = imp.find_module('_libdoma', [dirname(__file__)])
        except ImportError:
            import _libdoma
            return _libdoma
        if fp is not None:
            try:
                _mod = imp.load_module('_libdoma', fp, pathname, description)
            finally:
                fp.close()
            return _mod
    _libdoma = swig_import_helper()
    del swig_import_helper
else:
    import _libdoma
del version_info
try:
    _swig_property = property
except NameError:
    pass # Python < 2.2 doesn't have 'property'.
def _swig_setattr_nondynamic(self,class_type,name,value,static=1):
    if (name == "thisown"): return self.this.own(value)
    if (name == "this"):
        if type(value).__name__ == 'SwigPyObject':
            self.__dict__[name] = value
            return
    method = class_type.__swig_setmethods__.get(name,None)
    if method: return method(self,value)
    if (not static):
        self.__dict__[name] = value
    else:
        raise AttributeError("You cannot add attributes to %s" % self)

def _swig_setattr(self,class_type,name,value):
    return _swig_setattr_nondynamic(self,class_type,name,value,0)

def _swig_getattr(self,class_type,name):
    if (name == "thisown"): return self.this.own()
    method = class_type.__swig_getmethods__.get(name,None)
    if method: return method(self)
    raise AttributeError(name)

def _swig_repr(self):
    try: strthis = "proxy of " + self.this.__repr__()
    except: strthis = ""
    return "<%s.%s; %s >" % (self.__class__.__module__, self.__class__.__name__, strthis,)

try:
    _object = object
    _newclass = 1
except AttributeError:
    class _object : pass
    _newclass = 0



def check_whitelist(*args):
  return _libdoma.check_whitelist(*args)
check_whitelist = _libdoma.check_whitelist

def check_asn(*args):
  return _libdoma.check_asn(*args)
check_asn = _libdoma.check_asn

def check_home(*args):
  return _libdoma.check_home(*args)
check_home = _libdoma.check_home

def update(*args):
  return _libdoma.update(*args)
update = _libdoma.update

def asn_version():
  return _libdoma.asn_version()
asn_version = _libdoma.asn_version

def whitelist_version():
  return _libdoma.whitelist_version()
whitelist_version = _libdoma.whitelist_version

def get_cc_from_domain(*args):
  return _libdoma.get_cc_from_domain(*args)
get_cc_from_domain = _libdoma.get_cc_from_domain
class server_headers(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, server_headers, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, server_headers, name)
    __repr__ = _swig_repr
    __swig_setmethods__["http_code"] = _libdoma.server_headers_http_code_set
    __swig_getmethods__["http_code"] = _libdoma.server_headers_http_code_get
    if _newclass:http_code = _swig_property(_libdoma.server_headers_http_code_get, _libdoma.server_headers_http_code_set)
    __swig_setmethods__["clen"] = _libdoma.server_headers_clen_set
    __swig_getmethods__["clen"] = _libdoma.server_headers_clen_get
    if _newclass:clen = _swig_property(_libdoma.server_headers_clen_get, _libdoma.server_headers_clen_set)
    __swig_setmethods__["rurl"] = _libdoma.server_headers_rurl_set
    __swig_getmethods__["rurl"] = _libdoma.server_headers_rurl_get
    if _newclass:rurl = _swig_property(_libdoma.server_headers_rurl_get, _libdoma.server_headers_rurl_set)
    __swig_setmethods__["ctype"] = _libdoma.server_headers_ctype_set
    __swig_getmethods__["ctype"] = _libdoma.server_headers_ctype_get
    if _newclass:ctype = _swig_property(_libdoma.server_headers_ctype_get, _libdoma.server_headers_ctype_set)
    def __init__(self): 
        this = _libdoma.new_server_headers()
        try: self.this.append(this)
        except: self.this = this
    __swig_destroy__ = _libdoma.delete_server_headers
    __del__ = lambda self : None;
server_headers_swigregister = _libdoma.server_headers_swigregister
server_headers_swigregister(server_headers)

class httpbody(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, httpbody, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, httpbody, name)
    __repr__ = _swig_repr
    __swig_setmethods__["size"] = _libdoma.httpbody_size_set
    __swig_getmethods__["size"] = _libdoma.httpbody_size_get
    if _newclass:size = _swig_property(_libdoma.httpbody_size_get, _libdoma.httpbody_size_set)
    __swig_setmethods__["len"] = _libdoma.httpbody_len_set
    __swig_getmethods__["len"] = _libdoma.httpbody_len_get
    if _newclass:len = _swig_property(_libdoma.httpbody_len_get, _libdoma.httpbody_len_set)
    __swig_setmethods__["bodydata"] = _libdoma.httpbody_bodydata_set
    __swig_getmethods__["bodydata"] = _libdoma.httpbody_bodydata_get
    if _newclass:bodydata = _swig_property(_libdoma.httpbody_bodydata_get, _libdoma.httpbody_bodydata_set)
    def __init__(self): 
        this = _libdoma.new_httpbody()
        try: self.this.append(this)
        except: self.this = this
    __swig_destroy__ = _libdoma.delete_httpbody
    __del__ = lambda self : None;
httpbody_swigregister = _libdoma.httpbody_swigregister
httpbody_swigregister(httpbody)

class flux_entry(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, flux_entry, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, flux_entry, name)
    __repr__ = _swig_repr
    __swig_setmethods__["addr_str"] = _libdoma.flux_entry_addr_str_set
    __swig_getmethods__["addr_str"] = _libdoma.flux_entry_addr_str_get
    if _newclass:addr_str = _swig_property(_libdoma.flux_entry_addr_str_get, _libdoma.flux_entry_addr_str_set)
    __swig_setmethods__["cc"] = _libdoma.flux_entry_cc_set
    __swig_getmethods__["cc"] = _libdoma.flux_entry_cc_get
    if _newclass:cc = _swig_property(_libdoma.flux_entry_cc_get, _libdoma.flux_entry_cc_set)
    def __init__(self): 
        this = _libdoma.new_flux_entry()
        try: self.this.append(this)
        except: self.this = this
    __swig_destroy__ = _libdoma.delete_flux_entry
    __del__ = lambda self : None;
flux_entry_swigregister = _libdoma.flux_entry_swigregister
flux_entry_swigregister(flux_entry)


def get_asn(*args):
  return _libdoma.get_asn(*args)
get_asn = _libdoma.get_asn

def get_flux(*args):
  return _libdoma.get_flux(*args)
get_flux = _libdoma.get_flux
# This file is compatible with both classic and new-style classes.

