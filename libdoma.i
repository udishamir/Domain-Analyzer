%module libdoma

%{
#define SWIG_FILE_WITH_INIT
#include "libdoma.h"
%}

%include cpointer.i

%typemap(newfree) char * "free($1);";
%typemap(newfree) flux_entry * "release_flux($1);";

int check_whitelist(const char * domain);
int check_asn(const char * asn_list);
int check_home(const char * host, int verbose);

int update(char* download_path);

%newobject asn_version;
const char * asn_version(void);
%newobject whitelist_version;
const char * whitelist_version(void);
%newobject get_cc_from_domain; 
char * get_cc_from_domain(const char * domain);

%delobject destroy_flux_entry;

struct server_headers
{
	long http_code;
	double clen;
	char *rurl;
	char *ctype;
};
    
struct httpbody
{
	size_t size;
	size_t len;
	char *bodydata;
};

struct flux_entry
{
    char * addr_str;
    char cc[2];
};

%typemap(in, numinputs=0) (char **asn, char **asn_details)
{
  char *asn="", *asn_details="";
  $1 = &asn;
  $2 = &asn_details;
}

%typemap(argout) (char **asn, char **asn_details)
{
  PyObject *o = PyTuple_New(3);
  PyTuple_SetItem(o, 0, $result);
  PyTuple_SetItem(o, 1, PyString_FromString(*$1));
  PyTuple_SetItem(o, 2, PyString_FromString(*$2));
  
  $result = o;
}

int get_asn(const char * domain, char **asn, char **asn_details);  


%typemap(in, numinputs=0) (struct flux_entry **results)
{
  struct flux_entry *results;
  $1 = &results;
}

%typemap(argout) (struct flux_entry **results)
{
    PyObject *o = PyTuple_New(2);
    PyObject *list = PyList_New(0);
    PyTuple_SetItem(o, 0, $result);

    int i;
    for(i=0; (*$1)[i].addr_str ; i++)
    {
        PyObject *obj = SWIG_NewPointerObj(&((*$1)[i]), $descriptor(struct flux_entry*), 0 );
        PyList_Append(list, obj);
    }

    PyTuple_SetItem(o, 1, list);

    $result = o;
}

int get_flux(const char * domain, struct flux_entry ** results);
