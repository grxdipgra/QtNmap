#ifndef NMAP_H
#define NMAP_H
#include <QXmlStreamReader>
#include <QTemporaryFile>
#include "QProcess"
#include <QTemporaryFile>


struct NMapRun{
    QString scanner;
    QString args;
    QString start;
    QString startstr;
    QString version;
    QString xmloutputversion;
};
struct SCanInfo{
    QString type;
    QString protocol;
    int numservices;
    QString services;
};
struct Verbose{
    QString  level;
};
struct Debugging{
    QString  level;
};

struct Address{
    QString addr;
    QString addrtype;
};

struct State{
   QString state;
   QString reason;
   QString reason_ttl;
};
struct Service{
   QString name;
   QString method;
   QString conf;
};

struct Portused{
     QString state;
     QString proto;
     QString portid;
};

struct CPE{
    QString cpe;
};

struct OSClass{
    QString type;
    QString vendor;
    QString osfamily;
    QString osgen;
    QString accuracy;
    QList <CPE> cpe;
};

struct OSMatch{
     QString name;
     QString accuracy;
     QString line;
     QList <OSClass> osclass;
};

struct OS{
    QList <Portused> portused;
    QList <OSMatch> osmatch;
};

struct Status{
    QString state;
    QString reason;
    QString reason_ttl;
};

struct Times{
    QString srtt;
    QString rttvar;
    QString to;
};

struct  Extraports{
   QString state;
   QString count;
};

struct Extrareasons{
    QString reason;
    QString count;
};

struct Port{
    QString protocol;
    QString portid;
    State state;
    Service service;
};

struct Ports{
    Extraports extraports;
    Extrareasons extrareasons;
    QList<Port> port;
};

struct Uptime{
    QString seconds;
    QString lastboot;

};

struct Distance{
    QString value;
};


struct TcpSequence{
    QString index;
    QString difficulty;
    QString values;
};

struct IpIdSequence{
    QString klass;//class no se puede poner
    QString values;
};

struct TcpTsSequence{
    QString klass;//class no se puede poner
    QString values;
};

struct Host{
    QString starttime;
    QString endtime;
    Status status;
    Address address;
    Ports ports;
    OS os;
    Times times;
    Uptime uptime;
    Distance distance;
    TcpSequence tcpsequence;
    IpIdSequence ipidsecuence;
    TcpTsSequence tcptssequence;
};

struct Hosts{
    int up;
    int down;
    int total;

};

struct RunStats{
    QString time;
    QString timestr;
    QString elapsed;
    QString summary;
    QString exit;
    Hosts hosts;
};

struct NMapScan{
    NMapRun nmaprun;
    SCanInfo scaninfo;
    Verbose verbose;
    Debugging debuggin;
    QList<Host> host;
    RunStats runstats;
};



class NMap : public QXmlStreamReader {

public:
    NMap();

virtual ~NMap();

    void copy_nmapscan(NMapScan &tmp_nmapscan);
    void copy_reader(QXmlStreamReader &tmp_reader);

    void nmap_run_scan(QString opciones,QString equipos);
    //int nmap_numero_equipos();
    bool nmap_is_host_up(QString ip);
    int nmap_num_host_up();
    bool nmap_is_open_port(QString ip, QString port);
    QList <QString> nmap_hosts_up();
    QList <QString> nmap_ports_open(QString ip);
    bool is_linux(QString ip);
    bool is_win(QString ip);
    bool is_router(QString ip);
    bool is_printer(QString ip);


private:
    NMapScan nmapscan;
    QXmlStreamReader reader;
    void readXML();
    void nmap_host();
    void nmap_hosts();
    void nmap_verbose();
    void nmap_timesnmapscan();
    void nmap_debuggin();
    void nmap_address();
    void nmap_runstats();
    void nmap_nmaprun();
    void nmap_scaninfo();
    void nmap_host_host(Host &host);
    void nmap_hostname(Host &host);
    void nmap_address(Host &host);
    void nmap_status(Host &host);
    void nmap_ports(Host &host);
    void nmap_times(Host &host);
    void nmap_finished();
    void nmap_uptime(Host &host);
    void nmap_distance(Host &host);
    void nmap_tcpsequence(Host &host);
    void nmap_ipidsequence(Host &host);
    void nmap_tcptssequence(Host &host);
    void nmap_os(Host &host);
    void nmap_os_match(OSMatch &osmatch);
    void nmap_os_match_match(OSMatch &osmatch);
    void nmap_os_portused(Portused &portused);
    void nmap_os_osclass(OSClass &osclass);
    void nmap_os_osclass_osclass(OSClass &osclass);
    void nmap_os_cpe(OSClass &osclass);
    void nmap_port(Port &port);
    void nmap_ports_extraports(Host &host);
    void nmap_ports_extrareasons(Host &host);
    void nmap_port_port(Port &port);
    void nmap_port_state(Port &port);
    void nmap_port_service(Port &port);

};

#endif // NMAP_H
