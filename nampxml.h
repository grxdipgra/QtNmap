#ifndef NMAP_H
#define NMAP_H

#include <QXmlStreamReader>

class NMapReader : public QXmlStreamReader {

public:
    NMapReader();

virtual ~NMapReader();
    bool read (QIODevice *);
    void nmap_run();
    void nmap_scaninfo();
    void nmap_host();
    void nmap_address();
    void nmap_ports();
    void nmap_times();
    void nmap_runstats();
    void readXML();
};

#endif // NMAP_H
