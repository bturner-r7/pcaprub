#include "ruby.h"
#ifdef HAVE_RUBY_IO_H
#include "ruby/io.h"
#endif

#ifdef MAKE_TRAP
#include "rubysig.h"
#endif

#include "netifaces.h"

#include <pcap.h>
#if defined(WIN32)
#include <Win32-Extensions.h>
#endif

#if !defined(WIN32)
 #include <netinet/in.h>
 #include <arpa/inet.h>
 #include <sys/time.h>
#endif

static VALUE mPCAP;
static VALUE rb_cPcap, rb_cPkt;
static VALUE ePCAPRUBError, eDumperError, eBindingError, eBPFilterError;
void rbpcap_thread_wait_fd(int fno);

// Now defined in Native Ruby
// #define PCAPRUB_VERSION "*.*.*"

#define OFFLINE 1
#define LIVE 2

#if !defined(PCAP_NETMASK_UNKNOWN)
/*
* Version of libpcap < 1.1 
* Value to pass to pcap_compile() as the netmask if you dont know what the netmask is. 
*/
#define PCAP_NETMASK_UNKNOWN  0xffffffff
#endif

typedef struct rbpcap {
  pcap_t *pd;
  pcap_dumper_t *pdt;
  char iface[256];
  char type;
} rbpcap_t;


typedef struct rbpcapjob {
	struct pcap_pkthdr hdr;
  unsigned char *pkt;
	int wtf;
} rbpcapjob_t;

typedef struct rbpacket {
  struct pcap_pkthdr* hdr;
  u_char* pkt;
} rbpacket_t;

/*
* Return the name of a network device on the system.
*
* The pcap_lookupdev subroutine gets a network device suitable for use with the pcap_open_live and the pcap_lookupnet subroutines. If no interface can be found, or none are configured to be up, Null is returned. In the case of multiple network devices attached to the system, the pcap_lookupdev subroutine returns the first one it finds to be up, other than the loopback interface. (Loopback is always ignored.)
*/
static VALUE
rbpcap_s_lookupdev(VALUE self)
{
  char *dev = NULL;
  char eb[PCAP_ERRBUF_SIZE];
  VALUE ret_dev;  /* device string to return */
#if defined(WIN32)  /* pcap_lookupdev is broken on windows */    
  pcap_if_t *alldevs;
  pcap_if_t *d;

  /* Retrieve the device list from the local machine */
  if (pcap_findalldevs(&alldevs,eb) == -1) {
      rb_raise(eBindingError,"%s",eb);
  }

  /* Find the first interface with an address and not loopback */
  for(d = alldevs; d != NULL; d= d->next)  {
      if(d->name && d->addresses && !(d->flags & PCAP_IF_LOOPBACK)) {
          dev=d->name;
          break;
      }
  }
  
  if (dev == NULL) {
      rb_raise(eBindingError,"%s","No valid interfaces found, Make sure WinPcap is installed.\n");
  }
  ret_dev = rb_str_new2(dev);
  /* We don't need any more the device list. Free it */
  pcap_freealldevs(alldevs);
#else
  dev = pcap_lookupdev(eb);
  if (dev == NULL) {
	rb_raise(eBindingError, "%s", eb);
 }
  ret_dev = rb_str_new2(dev);
#endif
  return ret_dev;
}

static VALUE
rbpcap_s_lookupaddrs(VALUE self,VALUE dev)
{
    char *ldev = NULL;
    pcap_addr_t *addresses, *a = NULL;
    char eb[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *d;
    VALUE list;

    /* Retrieve the device list from the local machine */
    if (pcap_findalldevs(&alldevs,eb) == -1) {
        rb_raise(rb_eRuntimeError,"%s",eb);
    }

    /* Find the first interface with an address and not loopback */
    for(d = alldevs; d != NULL; d= d->next)  {
        if(strcmp(d->name,StringValuePtr(dev)) == 0 && d->addresses && !(d->flags & PCAP_IF_LOOPBACK)) {
            ldev=d->name;
	    addresses=d->addresses;
            break;
        }
    }
    
    if (ldev == NULL) {
        rb_raise(rb_eRuntimeError,"%s","No valid interfaces found.\n");
    }

    list = rb_ary_new();
    for(a = addresses; a != NULL; a= a->next)  {
      switch(a->addr->sa_family)
      {
         case AF_INET:
             if (a->addr)
                 rb_ary_push(list,  rb_str_new2(inet_ntoa((((struct sockaddr_in *)a->addr)->sin_addr))));
             break;
	/* Don't like the __MINGW32__ comment  for the moment need some testing ...
	  case AF_INET6:
	  #ifndef __MINGW32__ // Cygnus doesn't have IPv6 
             if (a->addr)
             printf("\tAddress: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
	  #endif
	    break;
	*/
	  default:
	      break;
      }
    }
    pcap_freealldevs(alldevs); 
    return(list);
}

/*
* Returns the network address and subnet mask for a network device.
*/
static VALUE
rbpcap_s_lookupnet(VALUE self, VALUE dev)
{
  bpf_u_int32 net, mask, m;
  struct in_addr addr;
  char eb[PCAP_ERRBUF_SIZE];
	VALUE list;
	
  Check_Type(dev, T_STRING);
  if (pcap_lookupnet(StringValuePtr(dev), &net, &mask, eb) == -1) {
	  rb_raise(rb_eRuntimeError, "%s", eb);
  }

  addr.s_addr = net;
  m = ntohl(mask);
  list = rb_ary_new();
	rb_ary_push(list, rb_str_new2((char *) inet_ntoa(addr)));
	rb_ary_push(list, UINT2NUM(m));
	return(list);
}

/*
* Check if PCAP file or device is bound and loaded 
*/
static int rbpcap_ready(rbpcap_t *rbp) {
	if(! rbp->pd) {
		rb_raise(ePCAPRUBError, "a device or pcap file must be opened first");
		return 0;
	}
	return 1;
}


/*
* Automated Garbage Collection for Pcap Class
*/
static void rbpcap_free(rbpcap_t *rbp) {
	if (rbp->pd)
		pcap_close(rbp->pd);
	
	if (rbp->pdt)
		pcap_dump_close(rbp->pdt);

	rbp->pd = NULL;
	rbp->pdt = NULL;
	free(rbp);
}

/*
* Automated Garbage Collection for Packet Class
*/
static void rbpacket_free(rbpacket_t *rbpacket)
{
  
  if(rbpacket->hdr != NULL) {
    rbpacket->hdr = NULL;
  }
  
  if(rbpacket->pkt != NULL) {
    rbpacket->pkt = NULL;
  }
  
  free(rbpacket);
}

/*
* Creates a new Pcap instance and returns the object itself.
*/
static VALUE
rbpcap_new_s(VALUE class)
{
  VALUE self;
  rbpcap_t *rbp;

  // need to make destructor do a pcap_close later
  self = Data_Make_Struct(class, rbpcap_t, 0, rbpcap_free, rbp);
  rb_obj_call_init(self, 0, 0);

  memset(rbp, 0, sizeof(rbpcap_t));

  return self;
}

/*
* Creates a new Packet instance and returns the object itself.
*/
static VALUE
rbpacket_new_s(VALUE class)
{
  VALUE self;
  rbpacket_t *rbpacket;

  // need to make destructor do a pcap_close later
  self = Data_Make_Struct(class, rbpacket_t, 0, rbpacket_free, rbpacket);
  rb_obj_call_init(self, 0, 0);

  memset(rbpacket, 0, sizeof(rbpacket_t));

  return self;
}


/*
* call-seq:
*   setmonitor(true)
*
* Set monitor mode for the capture.
*
* Returns the object itself.
*/
static VALUE
rbpcap_setmonitor(VALUE self, VALUE mode)
{
  rbpcap_t *rbp;
  int rfmon_mode = 0;
  Data_Get_Struct(self, rbpcap_t, rbp);
  if (mode == Qtrue) {
    rfmon_mode = 1;
  } else if (mode == Qfalse) {
    rfmon_mode = 0;
  } else {
    rb_raise(rb_eArgError, "Monitor mode must be a boolean");
  }

#if defined(WIN32)
  // monitor mode support was disabled in WinPcap 4.0.2
  rb_raise(ePCAPRUBError, "set monitor mode not supported in WinPcap");
#else
  if (pcap_set_rfmon(rbp->pd, rfmon_mode) == 0) {
    return self;
  } else {
    rb_raise(ePCAPRUBError, "unable to set monitor mode");
  }
#endif
}

/*
* call-seq:
*   settimeout(1234)
*
* Set timeout for the capture.
*
* Returns the object itself.
*/
static VALUE
rbpcap_settimeout(VALUE self, VALUE timeout)
{
  rbpcap_t *rbp;
  Data_Get_Struct(self, rbpcap_t, rbp);

  if(TYPE(timeout) != T_FIXNUM)
    rb_raise(rb_eArgError, "timeout must be a fixnum");

  if (pcap_set_timeout(rbp->pd, NUM2INT(timeout)) == 0) {
    return self;
  } else {
    rb_raise(ePCAPRUBError, "unable to set timeout");
  }
}


/*
* call-seq:
*   setsnaplen(true)
*
* Set snap length for the capture.
*
* Returns the object itself.
*/
static VALUE
rbpcap_setsnaplen(VALUE self, VALUE snaplen)
{
  rbpcap_t *rbp;
  Data_Get_Struct(self, rbpcap_t, rbp);

  if(TYPE(snaplen) != T_FIXNUM)
    rb_raise(rb_eArgError, "snaplen must be a fixnum");
  
  if (pcap_set_snaplen(rbp->pd, NUM2INT(snaplen)) == 0) {
    return self;
  } else {
    rb_raise(ePCAPRUBError, "unable to set snap length");
  }
}

/*
* call-seq:
*   setpromisc(true)
*
* Set promiscuous mode for the capture.
*
* Returns the object itself.
*/
static VALUE
rbpcap_setpromisc(VALUE self, VALUE mode)
{
  rbpcap_t *rbp;
  int promisc_mode = 0;
  Data_Get_Struct(self, rbpcap_t, rbp);
  if (mode == Qtrue) {
    promisc_mode = 1;
  } else if (mode == Qfalse) {
    promisc_mode = 0;
  } else {
    rb_raise(rb_eArgError, "Promisc mode must be a boolean");
  }

  if (pcap_set_promisc(rbp->pd, promisc_mode) == 0) {
    return self;
  } else {
    rb_raise(ePCAPRUBError, "unable to set promiscuous mode");
  }
}

/*
* call-seq:
*   setfilter(filter)
*
* Provide a valid bpf-filter to apply to the packet capture
* 
*  # Show me all SYN packets:
*  bpf-filter = "tcp[13] & 2 != 0"
*  capture.setfilter(bpf-filter)
* 
* Examples:
* * "net 10.0.0.0/8"
* * "not tcp and dst host 192.168.1.1"
*
* Returns the object itself.
*/
static VALUE
rbpcap_setfilter(VALUE self, VALUE filter)
{
  char eb[PCAP_ERRBUF_SIZE];
  rbpcap_t *rbp;
  u_int32_t mask = 0, netid = 0;
  struct bpf_program bpf;

  Data_Get_Struct(self, rbpcap_t, rbp);

  if(TYPE(filter) != T_STRING)
  	rb_raise(eBPFilterError, "filter must be a string");

	if(! rbpcap_ready(rbp)) return self; 
	
  if(rbp->type == LIVE)
  	if(pcap_lookupnet(rbp->iface, &netid, &mask, eb) < 0) {
  		netid = 0;
  		mask = 0;
  		rb_warn("unable to get IP: %s", eb);
  	}

  if(pcap_compile(rbp->pd, &bpf, RSTRING_PTR(filter), 0, mask) < 0)
  	rb_raise(eBPFilterError, "invalid bpf filter");

  if(pcap_setfilter(rbp->pd, &bpf) < 0)
  	rb_raise(eBPFilterError, "unable to set bpf filter");

  return self;
}

/*
* call-seq:
*   compile(filter)
*
* Raises an exception if "filter" has a syntax error
*
* Returns self if the filter is valid
*/
static VALUE
rbpcap_compile(VALUE self, VALUE filter) {
  struct bpf_program bpf;
  u_int32_t mask = 0;
  rbpcap_t *rbp;

  Data_Get_Struct(self, rbpcap_t, rbp);
  if(pcap_compile(rbp->pd, &bpf, RSTRING_PTR(filter), 0, mask) < 0) {
    rb_raise(eBPFilterError, "invalid bpf filter");
  } else {
    return self;
  }
}

/*
* Activate the interface
*
* call-seq:
*   activate() -> self
*
* Returns the object itself.
*/
static VALUE
rbpcap_activate(VALUE self)
{
  rbpcap_t *rbp;
  int errcode;
  Data_Get_Struct(self, rbpcap_t, rbp);
  
  if ((errcode = pcap_activate(rbp->pd)) == 0) {
    return self;
  } else {
    rb_raise(ePCAPRUBError, "unable to activate interface: %d, %s", errcode, rbp->iface);
  }
}


/*
* Close the interface
*
* call-seq:
*   activate() -> self
*
* Returns the object itself.
*/
static VALUE
rbpcap_close(VALUE self)
{
  rbpcap_t *rbp;
  Data_Get_Struct(self, rbpcap_t, rbp);
  
  pcap_close(rbp->pd);
  rbp->pd = NULL;
  return self;
}

static VALUE
rbpcap_create(VALUE self, VALUE iface)
{
  rbpcap_t *rbp;
  char eb[PCAP_ERRBUF_SIZE];

  Data_Get_Struct(self, rbpcap_t, rbp);

  rbp->type = LIVE;
  memset(rbp->iface, 0, sizeof(rbp->iface));
  strncpy(rbp->iface, RSTRING_PTR(iface), sizeof(rbp->iface) - 1);

  if(rbp->pd) {
    pcap_close(rbp->pd);  
  }

  rbp->pd = pcap_create(
    RSTRING_PTR(iface),
    eb
  );

  if(!rbp->pd)
    rb_raise(rb_eRuntimeError, "%s", eb);

  return self;
}

/*
* 
* call-seq:
*   create(iface) -> self
*
*   capture = ::Pcap.create(@dev)
*
* Returns the object itself.  
*/
static VALUE
rbpcap_create_s(VALUE class, VALUE iface)
{
  VALUE iPcap = rb_funcall(rb_cPcap, rb_intern("new"), 0);
  return rbpcap_create(iPcap, iface);
}



// transparent method
static VALUE
rbpcap_open_live(VALUE self, VALUE iface,VALUE snaplen,VALUE promisc, VALUE timeout)
{
  char eb[PCAP_ERRBUF_SIZE];
  rbpcap_t *rbp;
  int promisc_value = 0;

  if(TYPE(iface) != T_STRING)
  	rb_raise(rb_eArgError, "interface must be a string");
  if(TYPE(snaplen) != T_FIXNUM)
  	rb_raise(rb_eArgError, "snaplen must be a fixnum");
  if(TYPE(timeout) != T_FIXNUM)
  	rb_raise(rb_eArgError, "timeout must be a fixnum");

  switch(promisc) {
  	case Qtrue:
  		promisc_value = 1;
  		break;
  	case Qfalse:
  		promisc_value = 0;
  		break;
  	default:
  		rb_raise(ePCAPRUBError, "Promisc Argument not boolean");
  }

  Data_Get_Struct(self, rbpcap_t, rbp);


  rbp->type = LIVE;
  memset(rbp->iface, 0, sizeof(rbp->iface));
  strncpy(rbp->iface, RSTRING_PTR(iface), sizeof(rbp->iface) - 1);


  if(rbp->pd) {
      pcap_close(rbp->pd);	
  }

  rbp->pd = pcap_open_live(
  	RSTRING_PTR(iface),
  	NUM2INT(snaplen),
  	promisc_value,
  	NUM2INT(timeout),
  	eb
  );

  if(!rbp->pd)
  	rb_raise(rb_eRuntimeError, "%s", eb);

  return self;
}

/*
* 
* call-seq:
*   open_live(iface, snaplen, promisc, timeout) -> self
*
*   capture = ::Pcap.open_live(@dev, @snaplength, @promiscous_mode, @timeout)
*
* Returns the object itself.  
*/
static VALUE
rbpcap_open_live_s(VALUE class, VALUE iface, VALUE snaplen, VALUE promisc, VALUE timeout)
{
  VALUE iPcap = rb_funcall(rb_cPcap, rb_intern("new"), 0);
  return rbpcap_open_live(iPcap, iface, snaplen, promisc, timeout);
}

// transparent method
static VALUE
rbpcap_open_offline(VALUE self, VALUE filename)
{
  char eb[PCAP_ERRBUF_SIZE];
  rbpcap_t *rbp;

  if(TYPE(filename) != T_STRING)
  	rb_raise(rb_eArgError, "filename must be a string");

  Data_Get_Struct(self, rbpcap_t, rbp);

  memset(rbp->iface, 0, sizeof(rbp->iface));
  rbp->type = OFFLINE;

  rbp->pd = pcap_open_offline(
  	RSTRING_PTR(filename),
  	eb
  );

  if(!rbp->pd)
  	rb_raise(rb_eRuntimeError, "%s", eb);

  return self;
}

/*
* 
* call-seq:
*   open_offline(filename) -> self
*
*   capture = ::Pcap.open_offline(filename)  
*
* Returns the object itself.
*/
static VALUE
rbpcap_open_offline_s(VALUE class, VALUE filename)
{
  VALUE iPcap = rb_funcall(rb_cPcap, rb_intern("new"), 0);

  return rbpcap_open_offline(iPcap, filename);
}

// transparent method 
static VALUE
rbpcap_open_dead(VALUE self, VALUE linktype, VALUE snaplen)
{
  rbpcap_t *rbp;


  if(TYPE(linktype) != T_FIXNUM)
      rb_raise(rb_eArgError, "linktype must be a fixnum");
  if(TYPE(snaplen) != T_FIXNUM)
      rb_raise(rb_eArgError, "snaplen must be a fixnum");

  Data_Get_Struct(self, rbpcap_t, rbp);

  memset(rbp->iface, 0, sizeof(rbp->iface));
  rbp->type = OFFLINE;

  rbp->pd = pcap_open_dead(
      NUM2INT(linktype),
      NUM2INT(snaplen)
   );

  return self;
}


/*
* 
* call-seq:
*   open_dead(linktype, snaplen) -> self
*
* open a fake Pcap for compiling filters or opening a capture for output
*
* ::Pcap.open_dead() is used for creating a pcap structure to use when
* calling the other functions like compiling BPF code.
*
* * linktype specifies the link-layer type
*
* * snaplen specifies the snapshot length
*
* Returns the object itself.
*/
static VALUE
rbpcap_open_dead_s(VALUE class, VALUE linktype, VALUE snaplen)
{
  VALUE iPcap = rb_funcall(rb_cPcap, rb_intern("new"), 0);

  return rbpcap_open_dead(iPcap, linktype, snaplen);
}

/*
* call-seq:
*   dump_open(filename)
*
*  dump_open() is called to open a "savefile" for  writing
*/
static VALUE
rbpcap_dump_open(VALUE self, VALUE filename)
{
  rbpcap_t *rbp;

  if(TYPE(filename) != T_STRING)
     rb_raise(rb_eArgError, "filename must be a string");
      
  Data_Get_Struct(self, rbpcap_t, rbp);
  
  if(! rbpcap_ready(rbp)) return self;
  
  rbp->pdt = pcap_dump_open(
      rbp->pd,
      RSTRING_PTR(filename)
  );
  
  if(!rbp->pdt)
  	rb_raise(eDumperError, "Stream could not be initialized or opened.");
  
  return self;
}

/*
* call-seq:
*   dump_close()
*
*  dump_close() is called to manually close  a "savefile"
*/
static VALUE
rbpcap_dump_close(VALUE self)
{
  rbpcap_t *rbp;
  
  Data_Get_Struct(self, rbpcap_t, rbp);
  
  if(! rbpcap_ready(rbp)) return self;
  
  if(!rbp->pdt)
  	rb_raise(eDumperError, "Stream is already closed.");
  
  if (rbp->pdt)
	  pcap_dump_close(rbp->pdt);
	  
  rbp->pdt = NULL;  

  return self;
	
}


/*
* call-seq:
*   dump(caplen, pktlen, packet)
*
* not sure if this deviates too much from the way the rest of this class works?
*
* Writes packet capture date to a binary file assigned with dump_open().
*
* Returns the object itself.
*/
static VALUE
rbpcap_dump(VALUE self, VALUE caplen, VALUE pktlen, VALUE packet)
{
  rbpcap_t *rbp;
  struct pcap_pkthdr pcap_hdr;

  if(TYPE(packet) != T_STRING)
      rb_raise(rb_eArgError, "packet data must be a string");
  if(TYPE(caplen) != T_FIXNUM)
      rb_raise(rb_eArgError, "caplen must be a fixnum");
  if(TYPE(pktlen) != T_FIXNUM)
      rb_raise(rb_eArgError, "pktlen must be a fixnum");

  Data_Get_Struct(self, rbpcap_t, rbp);
  
  gettimeofday(&pcap_hdr.ts, NULL);
  pcap_hdr.caplen = NUM2UINT(caplen);
  pcap_hdr.len = NUM2UINT(pktlen);

//capture.next is yeilding an 8Bit ASCII  string 
//  ->  return rb_str_new((char *) job.pkt, job.hdr.caplen);
//Call dump such that capture.next{|pk| capture.dump(pk.length, pk.length, pk)}

  pcap_dump( 
      (u_char*)rbp->pdt,        
      &pcap_hdr,
      (unsigned char *)RSTRING_PTR(packet)
  );

  return self;
}



/*
* call-seq:
*   inject(payload)
*
* inject() transmit a raw packet through the network interface  
* 
* Returns the number of bytes written on success else raise failure.
*/
static VALUE
rbpcap_inject(VALUE self, VALUE payload)
{
  rbpcap_t *rbp;

  if(TYPE(payload) != T_STRING)
  	rb_raise(rb_eArgError, "payload must be a string");

  Data_Get_Struct(self, rbpcap_t, rbp);

	if(! rbpcap_ready(rbp)) return self; 
#if defined(WIN32)   
  /* WinPcap does not have a pcap_inject call we use pcap_sendpacket, if it suceedes 
   * we simply return the amount of packets request to inject, else we fail.
   */
  if(pcap_sendpacket(rbp->pd, RSTRING_PTR(payload), RSTRING_LEN(payload)) != 0) {
  	rb_raise(rb_eRuntimeError, "%s", pcap_geterr(rbp->pd));
  }
  return INT2NUM(RSTRING_LEN(payload));
#else
  return INT2NUM(pcap_inject(rbp->pd, RSTRING_PTR(payload), RSTRING_LEN(payload)));
#endif
}


/*
*
* Packet Job Call back from pcap_dispatch
*
*/

static void rbpcap_handler(rbpcapjob_t *job, struct pcap_pkthdr *hdr, u_char *pkt){
	job->pkt = (unsigned char *)pkt;
	job->hdr = *hdr;
}

/*
**
* Returns the next packet from the packet capture device.
* 
* Returns a string with the packet data.
*
* If the next_data() is unsuccessful, Null is returned.
*/
static VALUE
rbpcap_next_data(VALUE self)
{
	rbpcap_t *rbp;
	rbpcapjob_t job;
	char eb[PCAP_ERRBUF_SIZE];
	int ret;	
	
	Data_Get_Struct(self, rbpcap_t, rbp);
	
	if(! rbpcap_ready(rbp)) return self; 
	pcap_setnonblock(rbp->pd, 1, eb);

#ifdef MAKE_TRAP
	TRAP_BEG;
#endif

  // ret will contain the number of packets captured during the trap (ie one) since this is an iterator.
	ret = pcap_dispatch(rbp->pd, 1, (pcap_handler) rbpcap_handler, (u_char *)&job);

#ifdef MAKE_TRAP
	TRAP_END;
#endif

	if(rbp->type == OFFLINE && ret <= 0) 
	  return Qnil;

	if(ret > 0 && job.hdr.caplen > 0)
    return rb_str_new((char *) job.pkt, job.hdr.caplen);

	return Qnil;
}


/*
*
* Returns the next packet from the packet capture device.
* 
* Returns a string with the packet data.
*
* If the next_packet() is unsuccessful, Null is returned.
*/

static VALUE
rbpcap_next_packet(VALUE self)
{	
	rbpcap_t *rbp;
	rbpcapjob_t job;
	char eb[PCAP_ERRBUF_SIZE];
	int ret;	
	
	rbpacket_t* rbpacket;
	
	Data_Get_Struct(self, rbpcap_t, rbp);
	
	if(! rbpcap_ready(rbp)) return self; 

	pcap_setnonblock(rbp->pd, 1, eb);

#ifdef MAKE_TRAP
	TRAP_BEG;
#endif
  	
	ret = pcap_dispatch(rbp->pd, 1, (pcap_handler) rbpcap_handler, (u_char *)&job);

#ifdef MAKE_TRAP
	TRAP_END;
#endif

	if(rbp->type == OFFLINE && ret <= 0) 
	  return Qnil;

	if(ret > 0 && job.hdr.caplen > 0)
    {
      rbpacket = ALLOC(rbpacket_t);
      rbpacket->hdr = &job.hdr;
      rbpacket->pkt = (u_char *)&job.pkt;
      return Data_Wrap_Struct(rb_cPkt, 0, rbpacket_free, rbpacket);
    }

	return Qnil;
}


/*
* call-seq:
*   each_data() { |packet| ... } 
*
* Yields each packet from the capture to the passed-in block in turn.
*
*/
static VALUE
rbpcap_each_data(VALUE self)
{
  rbpcap_t *rbp;
  int fno = -1;
	
  Data_Get_Struct(self, rbpcap_t, rbp);

	if(! rbpcap_ready(rbp)) return self; 
	
#if defined(WIN32)
  fno = (int)pcap_getevent(rbp->pd);
#else
  fno = pcap_get_selectable_fd(rbp->pd);
#endif

  for(;;) {
  	VALUE packet = rbpcap_next_data(self);
  	if(packet == Qnil && rbp->type == OFFLINE) break;
  	packet == Qnil ? rbpcap_thread_wait_fd(fno) : rb_yield(packet);
  }

  return self;
}


/*
* call-seq:
*   each_packet() { |packet| ... } 
*
* Yields a PCAP::Packet from the capture to the passed-in block in turn.
*
*/
static VALUE
rbpcap_each_packet(VALUE self)
{
  rbpcap_t *rbp;
  int fno = -1;
	
  Data_Get_Struct(self, rbpcap_t, rbp);

	if(! rbpcap_ready(rbp)) return self; 
	
#if defined(WIN32)
  fno = (int)pcap_getevent(rbp->pd);
#else
  fno = pcap_get_selectable_fd(rbp->pd);
#endif

  for(;;) {
  	VALUE packet = rbpcap_next_packet(self);
  	if(packet == Qnil && rbp->type == OFFLINE) break;
  	packet == Qnil ? rbpcap_thread_wait_fd(fno) : rb_yield(packet);
  }

  return self;
}


/*
* call-seq:
*   datalink()
*
* Returns the integer datalink value unless capture 
* 
*   foo.bar unless capture.datalink == Pcap::DLT_EN10MB
*/
static VALUE
rbpcap_datalink(VALUE self)
{
  rbpcap_t *rbp;

  Data_Get_Struct(self, rbpcap_t, rbp);

	if(! rbpcap_ready(rbp)) return self;
	
  return INT2NUM(pcap_datalink(rbp->pd));
}

/*
* call-seq:
*   pcap_major_version()
*
* Returns the integer PCAP MAJOR LIBRARY value unless capture 
* 
*/
static VALUE
rbpcap_major_version(VALUE self)
{
  rbpcap_t *rbp;

  Data_Get_Struct(self, rbpcap_t, rbp);
	
	if(! rbpcap_ready(rbp)) return self;
	
  return INT2NUM(pcap_major_version(rbp->pd));
}

/*
* call-seq:
*   pcap_minor_version()
*
* Returns the integer PCAP MINOR LIBRARY value unless capture 
* 
*/
static VALUE
rbpcap_minor_version(VALUE self)
{
  rbpcap_t *rbp;

  Data_Get_Struct(self, rbpcap_t, rbp);
	
	if(! rbpcap_ready(rbp)) return self;
	
  return INT2NUM(pcap_minor_version(rbp->pd));
}

/*
* call-seq:
*   snapshot()
*
* Returns the snapshot length, which is the number of bytes to save for each packet captured.
* 
*/
static VALUE
rbpcap_snapshot(VALUE self)
{
  rbpcap_t *rbp;

  Data_Get_Struct(self, rbpcap_t, rbp);

	if(! rbpcap_ready(rbp)) return self;
	
  return INT2NUM(pcap_snapshot(rbp->pd));
}

/*
* call-seq:
*   stats()
*
* Returns a hash with statistics of the packet capture
*
* - ["recv"] # number of packets received
* - ["drop"] # number of packets dropped 
* - ["idrop"] # number of packets dropped by interface
* 
*/
static VALUE
rbpcap_stats(VALUE self)
{
  rbpcap_t *rbp;
  struct pcap_stat stat;
  VALUE hash;
  
  Data_Get_Struct(self, rbpcap_t, rbp);

	if(! rbpcap_ready(rbp)) return self;
		
  if (pcap_stats(rbp->pd, &stat) == -1)
  	return Qnil;
  	
  hash = rb_hash_new();
  rb_hash_aset(hash, rb_str_new2("recv"), UINT2NUM(stat.ps_recv));
  rb_hash_aset(hash, rb_str_new2("drop"), UINT2NUM(stat.ps_drop));
  rb_hash_aset(hash, rb_str_new2("idrop"), UINT2NUM(stat.ps_ifdrop));
  // drops by interface XXX not yet supported under pcap.h 2.4

//#if defined(WIN32)
//    rb_hash_aset(hash, rb_str_new2("bs_capt"), UINT2NUM(stat.bs_capt));
//#endif    
    
  return hash;
}

/*
*
* Returns the EPOCH integer from the ts.tv_sec record in the PCAP::Packet header  
* 
*/
static VALUE 
rbpacket_time(VALUE self)
{
  rbpacket_t* rbpacket;
  Data_Get_Struct(self, rbpacket_t, rbpacket);
  return INT2NUM(rbpacket->hdr->ts.tv_sec);
}

/*
*
* Returns the tv_usec integer from the ts.tv_usec record in the PCAP::Packet header  
* timestamp microseconds 
* the microseconds when this packet was captured, as an offset to ts_sec. 
* Beware: this value shouldn't reach 1 second (1 000 000), in this case ts_sec must be increased instead! 
*
* Ruby Microsecond Handling
* Time.at(946684800.2).usec #=> 200000
* Time.now.usec
*/

static VALUE 
rbpacket_microsec(VALUE self)
{
  rbpacket_t* rbpacket;
  Data_Get_Struct(self, rbpacket_t, rbpacket);
  return INT2NUM(rbpacket->hdr->ts.tv_usec);
}


/*
*
* Returns the integer length of packet length field from the in the PCAP::Packet header 
* 
*/
static VALUE 
rbpacket_length(VALUE self)
{
  rbpacket_t* rbpacket;
  Data_Get_Struct(self, rbpacket_t, rbpacket);
  return INT2NUM(rbpacket->hdr->len);
}

/*
*
* Returns the integer length of capture len from the in the PCAP::Packet header 
* 
*/
static VALUE 
rbpacket_caplen(VALUE self)
{
  rbpacket_t* rbpacket;
  Data_Get_Struct(self, rbpacket_t, rbpacket);

  if (rbpacket->hdr == NULL)
    return Qnil;

  //test incorrect case
  if (rbpacket->hdr->caplen > rbpacket->hdr->len)
    return INT2NUM(rbpacket->hdr->len);

  return INT2NUM(rbpacket->hdr->caplen);
}

/*
*
* Returns the integer PCAP MINOR LIBRARY value unless capture 
* 
*/
static VALUE 
rbpacket_data(VALUE self)
{
  rbpacket_t* rbpacket;
  Data_Get_Struct(self, rbpacket_t, rbpacket);

  if ((rbpacket->pkt == NULL) || (rbpacket->hdr == NULL) || (rbpacket->hdr->caplen > rbpacket->hdr->len))
    return Qnil;

  return rb_str_new((char *) rbpacket->pkt, rbpacket->hdr->caplen); 
}

#if defined(WIN32)
static VALUE
rbpcap_thread_wait_handle_blocking(void *data)
{
  VALUE result;
  result = (VALUE)WaitForSingleObject(data, -1);
  return result;
}
#endif

void
rbpcap_thread_wait_fd(int fno)
{
#if defined(WIN32)
#ifdef HAVE_RB_THREAD_BLOCKING_REGION
  rb_thread_blocking_region(
      rbpcap_thread_wait_handle_blocking,
      (HANDLE)fno, RUBY_UBF_IO, 0);
#else
  rb_thread_polling();
#endif
#else
#ifdef HAVE_RB_WAIT_FOR_SINGLE_FD
  int result = 0;
  if (fno < 0) {
    rb_raise(rb_eIOError, "closed stream");
  }
  result = rb_wait_for_single_fd(fno, RB_WAITFD_IN, NULL);
  if (result < 0) {
    rb_sys_fail(0);
  }
#else
  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(fno, &rfds);
  rb_thread_select(fno + 1, &rfds, NULL, NULL, NULL);
#endif
#endif
}

void
Init_pcaprub()
{
  /*
  * Document-class: Pcap
  * 
  * Main class defined by the pcaprub extension.
  */
  mPCAP = rb_define_module("PCAPRUB");
  
  rb_cPcap = rb_define_class_under(mPCAP,"Pcap", rb_cObject);
  rb_cPkt = rb_define_class_under(mPCAP,"Packet", rb_cObject);
  
  ePCAPRUBError = rb_path2class("PCAPRUB::PCAPRUBError");
  eBindingError = rb_path2class("PCAPRUB::BindingError");
  eBPFilterError = rb_path2class("PCAPRUB::BPFError");
  eDumperError = rb_path2class("PCAPRUB::DumperError");
  
  rb_define_module_function(rb_cPcap, "lookupdev", rbpcap_s_lookupdev, 0);  
  rb_define_module_function(rb_cPcap, "lookupnet", rbpcap_s_lookupnet, 1);
  rb_define_module_function(rb_cPcap, "lookupaddrs", rbpcap_s_lookupaddrs, 1);
	
  rb_define_const(rb_cPcap, "DLT_NULL",   INT2NUM(DLT_NULL));
  rb_define_const(rb_cPcap, "DLT_EN10MB", INT2NUM(DLT_EN10MB));
  rb_define_const(rb_cPcap, "DLT_EN3MB", INT2NUM(DLT_EN3MB));
  rb_define_const(rb_cPcap, "DLT_AX25", INT2NUM(DLT_AX25));
  rb_define_const(rb_cPcap, "DLT_PRONET", INT2NUM(DLT_PRONET));
  rb_define_const(rb_cPcap, "DLT_CHAOS", INT2NUM(DLT_CHAOS));
  rb_define_const(rb_cPcap, "DLT_IEEE802", INT2NUM(DLT_IEEE802));
  rb_define_const(rb_cPcap, "DLT_ARCNET", INT2NUM(DLT_ARCNET));
  rb_define_const(rb_cPcap, "DLT_SLIP", INT2NUM(DLT_SLIP));
  rb_define_const(rb_cPcap, "DLT_PPP", INT2NUM(DLT_PPP));
  rb_define_const(rb_cPcap, "DLT_FDDI", INT2NUM(DLT_FDDI));
  rb_define_const(rb_cPcap, "DLT_ATM_RFC1483", INT2NUM(DLT_ATM_RFC1483));
  rb_define_const(rb_cPcap, "DLT_RAW", INT2NUM(DLT_RAW));
  rb_define_const(rb_cPcap, "DLT_SLIP_BSDOS", INT2NUM(DLT_SLIP_BSDOS));
  rb_define_const(rb_cPcap, "DLT_PPP_BSDOS", INT2NUM(DLT_PPP_BSDOS));
  rb_define_const(rb_cPcap, "DLT_IEEE802_11", INT2NUM(DLT_IEEE802_11));
  rb_define_const(rb_cPcap, "DLT_IEEE802_11_RADIO", INT2NUM(DLT_IEEE802_11_RADIO));
  rb_define_const(rb_cPcap, "DLT_IEEE802_11_RADIO_AVS", INT2NUM(DLT_IEEE802_11_RADIO_AVS));
  rb_define_const(rb_cPcap, "DLT_LINUX_SLL", INT2NUM(DLT_LINUX_SLL));
  rb_define_const(rb_cPcap, "DLT_PRISM_HEADER", INT2NUM(DLT_PRISM_HEADER));
  rb_define_const(rb_cPcap, "DLT_AIRONET_HEADER", INT2NUM(DLT_AIRONET_HEADER));
  /* Pcap Error Codes 
   * Error codes for the pcap API.
   * These will all be negative, so you can check for the success or
   * failure of a call that returns these codes by checking for a
   * negative value.
   */
  rb_define_const(rb_cPcap, "PCAP_ERROR", INT2NUM(PCAP_ERROR)); /* generic error code */
  rb_define_const(rb_cPcap, "PCAP_ERROR_BREAK", INT2NUM(PCAP_ERROR_BREAK)); /* loop terminated by pcap_breakloop */
  rb_define_const(rb_cPcap, "PCAP_ERROR_NOT_ACTIVATED", INT2NUM(PCAP_ERROR_NOT_ACTIVATED));	/* the capture needs to be activated */
  rb_define_const(rb_cPcap, "PCAP_ERROR_ACTIVATED", INT2NUM(PCAP_ERROR_ACTIVATED));	/* the operation can't be performed on already activated captures */
  rb_define_const(rb_cPcap, "PCAP_ERROR_NO_SUCH_DEVICE", INT2NUM(PCAP_ERROR_NO_SUCH_DEVICE));	/* no such device exists */
  rb_define_const(rb_cPcap, "PCAP_ERROR_RFMON_NOTSUP", INT2NUM(PCAP_ERROR_RFMON_NOTSUP));	/* this device doesn't support rfmon (monitor) mode */
  rb_define_const(rb_cPcap, "PCAP_ERROR_NOT_RFMON", INT2NUM(PCAP_ERROR_NOT_RFMON));	/* operation supported only in monitor mode */
  rb_define_const(rb_cPcap, "PCAP_ERROR_PERM_DENIED", INT2NUM(PCAP_ERROR_PERM_DENIED));	/* no permission to open the device */
  rb_define_const(rb_cPcap, "PCAP_ERROR_IFACE_NOT_UP", INT2NUM(PCAP_ERROR_IFACE_NOT_UP));	/* interface isn't up */

  /*
   * Warning codes for the pcap API.
   * These will all be positive and non-zero, so they won't look like
   * errors.
   */
  rb_define_const(rb_cPcap, "PCAP_WARNING", INT2NUM(PCAP_WARNING));	/* generic warning code */
  rb_define_const(rb_cPcap, "PCAP_WARNING_PROMISC_NOTSUP", INT2NUM(PCAP_WARNING_PROMISC_NOTSUP));	/* this device doesn't support promiscuous mode */

  /*
   * Value to pass to pcap_compile() as the netmask if you don't know what
   * the netmask is.
   */
  rb_define_const(rb_cPcap, "PCAP_NETMASK_UNKNOWN", INT2NUM(PCAP_NETMASK_UNKNOWN));


  rb_define_singleton_method(rb_cPcap, "new", rbpcap_new_s, 0);
  rb_define_singleton_method(rb_cPcap, "create", rbpcap_create_s, 1);
  rb_define_singleton_method(rb_cPcap, "open_live", rbpcap_open_live_s, 4);
  rb_define_singleton_method(rb_cPcap, "open_offline", rbpcap_open_offline_s, 1);
  rb_define_singleton_method(rb_cPcap, "open_dead", rbpcap_open_dead_s, 2);
  
  rb_define_method(rb_cPcap, "dump_open", rbpcap_dump_open, 1);
  rb_define_method(rb_cPcap, "dump_close", rbpcap_dump_close, 0);
  rb_define_method(rb_cPcap, "dump", rbpcap_dump, 3);
  rb_define_method(rb_cPcap, "each_data", rbpcap_each_data, 0);
  rb_define_method(rb_cPcap, "next_data", rbpcap_next_data, 0);
  rb_define_method(rb_cPcap, "each_packet", rbpcap_each_packet, 0);
  rb_define_method(rb_cPcap, "next_packet", rbpcap_next_packet, 0);

  /*
  * Document-method: each
  * Alias of each_data
  */
  rb_define_method(rb_cPcap, "each", rbpcap_each_data, 0);
  /*
  * Document-method: next
  * Alias of next_data
  */

  rb_define_method(rb_cPcap, "next", rbpcap_next_data, 0);
  rb_define_method(rb_cPcap, "setfilter", rbpcap_setfilter, 1);
  rb_define_method(rb_cPcap, "compile", rbpcap_compile, 1);
  rb_define_method(rb_cPcap, "setmonitor", rbpcap_setmonitor, 1);
  rb_define_method(rb_cPcap, "setsnaplen", rbpcap_setsnaplen, 1);
  rb_define_method(rb_cPcap, "settimeout", rbpcap_settimeout, 1);
  rb_define_method(rb_cPcap, "setpromisc", rbpcap_setpromisc, 1);
  rb_define_method(rb_cPcap, "activate", rbpcap_activate, 0);
  rb_define_method(rb_cPcap, "inject", rbpcap_inject, 1);
  rb_define_method(rb_cPcap, "datalink", rbpcap_datalink, 0);
  rb_define_method(rb_cPcap, "pcap_major_version", rbpcap_major_version, 0);
  rb_define_method(rb_cPcap, "pcap_minor_version", rbpcap_minor_version, 0);
  rb_define_method(rb_cPcap, "snapshot", rbpcap_snapshot, 0);
  rb_define_method(rb_cPcap, "close", rbpcap_close, 0);

  /*
  * Document-method: snaplen
  * Alias of snapshot
  */
  rb_define_method(rb_cPcap, "snaplen", rbpcap_snapshot, 0);
  rb_define_method(rb_cPcap, "stats", rbpcap_stats, 0);
  
  rb_define_singleton_method(rb_cPkt, "new", rbpacket_new_s, 0);
  
  rb_define_method(rb_cPkt, "time", rbpacket_time, 0);
  rb_define_method(rb_cPkt, "microsec", rbpacket_microsec, 0);
  rb_define_method(rb_cPkt, "length", rbpacket_length, 0);
  rb_define_method(rb_cPkt, "caplen", rbpacket_caplen, 0);
  rb_define_method(rb_cPkt, "data", rbpacket_data, 0);
  /*
  * Document-method: to_s
  * Alias of data
  */
  rb_define_method(rb_cPkt, "to_s", rbpacket_data, 0);

  //Netifaces
	rb_define_module_function(rb_cPcap, "interfaces", rbnetifaces_s_interfaces, 0);
	rb_define_module_function(rb_cPcap, "addresses", rbnetifaces_s_addresses, 1);
	rb_define_module_function(rb_cPcap, "interface_info", rbnetifaces_s_interface_info, 1);

	//constants
	// Address families (auto-detect using #ifdef)

#ifdef AF_INET
	rb_define_const(rb_cPcap, "AF_INET", INT2NUM(AF_INET));
#endif
#ifdef AF_INET6
	rb_define_const(rb_cPcap, "AF_INET6", INT2NUM(AF_INET6));
#endif
#ifdef AF_UNSPEC
	rb_define_const(rb_cPcap, "AF_UNSPEC", INT2NUM(AF_UNSPEC));
#endif
#ifdef AF_UNIX
	rb_define_const(rb_cPcap, "AF_UNIX", INT2NUM(AF_UNIX));
#endif
#ifdef AF_FILE
	rb_define_const(rb_cPcap, "AF_FILE", INT2NUM(AF_FILE));
#endif

#ifdef AF_AX25
	rb_define_const(rb_cPcap, "AF_AX25", INT2NUM(AF_AX25));
#endif
#ifdef AF_IMPLINK
	rb_define_const(rb_cPcap, "AF_IMPLINK", INT2NUM(AF_IMPLINK));
#endif
#ifdef AF_PUP
	rb_define_const(rb_cPcap, "AF_PUP", INT2NUM(AF_PUP));
#endif
#ifdef AF_CHAOS
	rb_define_const(rb_cPcap, "AF_CHAOS", INT2NUM(AF_CHAOS));
#endif
#ifdef AF_NS
	rb_define_const(rb_cPcap, "AF_NS", INT2NUM(AF_NS));
#endif
#ifdef AF_ISO
	rb_define_const(rb_cPcap, "AF_ISO", INT2NUM(AF_ISO));
#endif
#ifdef AF_ECMA
	rb_define_const(rb_cPcap, "AF_ECMA", INT2NUM(AF_ECMA));
#endif
#ifdef AF_DATAKIT
	rb_define_const(rb_cPcap, "AF_DATAKIT", INT2NUM(AF_DATAKIT));
#endif
#ifdef AF_CCITT
	rb_define_const(rb_cPcap, "AF_CCITT", INT2NUM(AF_CCITT));
#endif
#ifdef AF_SNA
	rb_define_const(rb_cPcap, "AF_SNA", INT2NUM(AF_SNA));
#endif
#ifdef AF_DECnet
	rb_define_const(rb_cPcap, "AF_DECnet", INT2NUM(AF_DECnet));
#endif
#ifdef AF_DLI
	rb_define_const(rb_cPcap, "AF_DLI", INT2NUM(AF_DLI));
#endif
#ifdef AF_LAT
	rb_define_const(rb_cPcap, "AF_LAT", INT2NUM(AF_LAT));
#endif
#ifdef AF_HYLINK
	rb_define_const(rb_cPcap, "AF_HYLINK", INT2NUM(AF_HYLINK));
#endif
#ifdef AF_APPLETALK
	rb_define_const(rb_cPcap, "AF_APPLETALK", INT2NUM(AF_APPLETALK));
#endif
#ifdef AF_ROUTE
	rb_define_const(rb_cPcap, "AF_ROUTE", INT2NUM(AF_ROUTE));
#endif
#ifdef AF_LINK
	rb_define_const(rb_cPcap, "AF_LINK", INT2NUM(AF_LINK));
#endif
#ifdef AF_PACKET
	rb_define_const(rb_cPcap, "AF_PACKET", INT2NUM(AF_PACKET));
#endif
#ifdef AF_COIP
	rb_define_const(rb_cPcap, "AF_COIP", INT2NUM(AF_COIP));
#endif
#ifdef AF_CNT
	rb_define_const(rb_cPcap, "AF_CNT", INT2NUM(AF_CNT));
#endif
#ifdef AF_IPX
	rb_define_const(rb_cPcap, "AF_IPX", INT2NUM(AF_IPX));
#endif
#ifdef AF_SIP
	rb_define_const(rb_cPcap, "AF_SIP", INT2NUM(AF_SIP));
#endif
#ifdef AF_NDRV
	rb_define_const(rb_cPcap, "AF_NDRV", INT2NUM(AF_NDRV));
#endif
#ifdef AF_ISDN
	rb_define_const(rb_cPcap, "AF_ISDN", INT2NUM(AF_ISDN));
#endif
#ifdef AF_NATM
	rb_define_const(rb_cPcap, "AF_NATM", INT2NUM(AF_NATM));
#endif
#ifdef AF_SYSTEM
	rb_define_const(rb_cPcap, "AF_SYSTEM", INT2NUM(AF_SYSTEM));
#endif
#ifdef AF_NETBIOS
	rb_define_const(rb_cPcap, "AF_NETBIOS", INT2NUM(AF_NETBIOS));
#endif
#ifdef AF_NETBEUI
	rb_define_const(rb_cPcap, "AF_NETBEUI", INT2NUM(AF_NETBEUI));
#endif
#ifdef AF_PPP
	rb_define_const(rb_cPcap, "AF_PPP", INT2NUM(AF_PPP));
#endif
#ifdef AF_ATM
	rb_define_const(rb_cPcap, "AF_ATM", INT2NUM(AF_ATM));
#endif
#ifdef AF_ATMPVC
	rb_define_const(rb_cPcap, "AF_ATMPVC", INT2NUM(AF_ATMPVC));
#endif
#ifdef AF_ATMSVC
	rb_define_const(rb_cPcap, "AF_ATMSVC", INT2NUM(AF_ATMSVC));
#endif
#ifdef AF_NETGRAPH
	rb_define_const(rb_cPcap, "AF_NETGRAPH", INT2NUM(AF_NETGRAPH));
#endif
#ifdef AF_VOICEVIEW
	rb_define_const(rb_cPcap, "AF_VOICEVIEW", INT2NUM(AF_VOICEVIEW));
#endif
#ifdef AF_FIREFOX
	rb_define_const(rb_cPcap, "AF_FIREFOX", INT2NUM(AF_FIREFOX));
#endif
#ifdef AF_UNKNOWN1
	rb_define_const(rb_cPcap, "AF_UNKNOWN1", INT2NUM(AF_UNKNOWN1));
#endif
#ifdef AF_BAN
	rb_define_const(rb_cPcap, "AF_BAN", INT2NUM(AF_BAN));
#endif
#ifdef AF_CLUSTER
	rb_define_const(rb_cPcap, "AF_CLUSTER", INT2NUM(AF_CLUSTER));
#endif
#ifdef AF_12844
	rb_define_const(rb_cPcap, "AF_12844", INT2NUM(AF_12844));
#endif
#ifdef AF_IRDA
	rb_define_const(rb_cPcap, "AF_IRDA", INT2NUM(AF_IRDA));
#endif
#ifdef AF_NETDES
	rb_define_const(rb_cPcap, "AF_NETDES", INT2NUM(AF_NETDES));
#endif
#ifdef AF_NETROM
	rb_define_const(rb_cPcap, "AF_NETROM", INT2NUM(AF_NETROM));
#endif
#ifdef AF_BRIDGE
	rb_define_const(rb_cPcap, "AF_BRIDGE", INT2NUM(AF_BRIDGE));
#endif
#ifdef AF_X25
	rb_define_const(rb_cPcap, "AF_X25", INT2NUM(AF_X25));
#endif
#ifdef AF_ROSE
	rb_define_const(rb_cPcap, "AF_ROSE", INT2NUM(AF_ROSE));
#endif
#ifdef AF_SECURITY
	rb_define_const(rb_cPcap, "AF_SECURITY", INT2NUM(AF_SECURITY));
#endif
#ifdef AF_KEY
	rb_define_const(rb_cPcap, "AF_KEY", INT2NUM(AF_KEY));
#endif
#ifdef AF_NETLINK
	rb_define_const(rb_cPcap, "AF_NETLINK", INT2NUM(AF_NETLINK));
#endif
#ifdef AF_ASH
	rb_define_const(rb_cPcap, "AF_ASH", INT2NUM(AF_ASH));
#endif
#ifdef AF_ECONET
	rb_define_const(rb_cPcap, "AF_ECONET", INT2NUM(AF_ECONET));
#endif
#ifdef AF_PPPOX
	rb_define_const(rb_cPcap, "AF_PPPOX", INT2NUM(AF_PPPOX));
#endif
#ifdef AF_WANPIPE
	rb_define_const(rb_cPcap, "AF_WANPIPE", INT2NUM(AF_WANPIPE));
#endif
#ifdef AF_BLUETOOTH
	rb_define_const(rb_cPcap, "AF_BLUETOOTH", INT2NUM(AF_BLUETOOTH));
#endif

}
