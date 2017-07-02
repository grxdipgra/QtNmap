#include "nmap_xml.h"
#include <QXmlStreamReader>
#include <QTemporaryFile>
#include "QProcess"
#include "qdebug.h"


NMap::NMap():QXmlStreamReader(){//Constructor

}

NMap::~NMap() {//Destructor
}

/****************copy_nmapscan*****************************
 * Copia en tmp_nmapscan el struct NMapScan,
 * donde se guardan todos los datos de la consulta de nmap
 * *******************************************************/

void NMap::copy_nmapscan(NMapScan &tmp_nmapscan) {
   tmp_nmapscan = nmapscan;

}

/*******************************nmap_ejecuta_scan*************************************
 * Realiza el escaneo de equipos y puertos pasados por parametro.
 * El resultado lo guarda en reader, que es de tipo QXmlStreamReader
 ************************************************************************************/
void NMap::nmap_run_scan(QString opciones, QString equipos){
    QTemporaryFile file;
    if (file.open()) {
        QProcess process;
        process.start ("nmap "+opciones+" -oX "+file.fileName() +" "+equipos);
        process.waitForFinished(-1);
        reader.addData(file.readAll());
        file.close();
       }
    else
        qDebug() << "No se ha podido abrir el fichero necesario  ";

    readXML();
}

/******************************nmap_num_host_up********************************
 * Devuelve el número de equipos encontrados
 * ***************************************************************************/
int NMap::nmap_num_host_up(){

    return nmapscan.host.count();
}

/***************************nmap_is_open_port_nmapscan************************
 * Devuelve true si el puerto port esta abierto en el equipo pasado por ip
 * Usa nmapscan, es decir necesita haber hecho la busqueda nmap antes
 * **************************************************************************/

bool NMap::nmap_is_open_port (QString ip, QString port){
    int i,j,num_equipos,num_port;
    num_equipos = nmap_num_host_up();
    for (i=0;i<num_equipos;i++){
        num_port = nmapscan.host[i].ports.port.count();
        for (j=0;j<num_port;j++){
        if ((nmapscan.host[i].address.addr == ip) && (nmapscan.host[i].ports.port[j].state.state == "open") && (nmapscan.host[i].ports.port[j].portid == port))
             return true;
        }
    }
return false;
}

/************************nmap_hosts_up***************************************
 * Devuelve el listado de ip's que estan activos en un QList <QString>
 * *************************************************************************/

QList <QString> NMap::nmap_hosts_up(){
    QList  <QString> lista;
    int num_equipos;
    num_equipos = nmap_num_host_up();
    for (int i=0;i<num_equipos;i++)
        lista.append(nmapscan.host[i].address.addr);
return lista;
}

/************************nmap_port_open***************************************
 * Devuelve los puertos abiertos de la ip pasada por parametro
 * *************************************************************************/
QList <QString> NMap::nmap_ports_open(QString ip){
    QList  <QString> puertos;
    int num_equipos;
    num_equipos = nmap_num_host_up();
    for (int i=0;i<num_equipos;i++)
        if ((nmapscan.host[i].address.addr)==ip)
            for (int j=0;j<nmapscan.host[i].ports.port.count();j++)
                if (nmapscan.host[i].ports.port[j].state.state=="open")
                    puertos.append(nmapscan.host[i].ports.port[j].portid);
return puertos;
}

/************************nmap_hosts_up***************************************
 * Devuelve true si la ip pasada por parametro está en la lista de host up
 * *************************************************************************/
bool NMap::nmap_is_host_up (QString ip){
    QList<QString> equipos;
    QList<QString>::iterator i;
    equipos=nmap_hosts_up();
    for (i = equipos.begin(); i != equipos.end() ; ++i){
        if (ip==*i)
            return true;
    }
    return false;
}

/************************is_linux***************************************
 * Devuelve true si el equipo tiene el puerto 8080 abierto
 * *************************************************************************/
bool NMap::is_linux (QString ip){
    return nmap_is_open_port(ip,"8080");
}
/************************is_win***************************************
 * Devuelve true si el equipo tiene el puerto rpc abierto
 * *************************************************************************/
bool NMap::is_win (QString ip){
    if ((nmap_is_open_port(ip,"139")) && (nmap_is_open_port(ip,"445")))
         return true;
return false;
}

/************************is_linux***************************************
 * Devuelve true si el equipo es un router (lo mas probable)
 * *************************************************************************/
bool NMap::is_router (QString ip){
    if (((ip.split(".")[0])=="10") && ((ip.split(".")[3])=="254"))
        return true;
    if (((ip=="192.168.1.1")||(ip=="192.168.0.1")) && (nmap_is_open_port(ip,"80")||nmap_is_open_port(ip,"23")))
        return true;

return false;
}

/************************nmap_hosts_up***************************************
 * Devuelve true si el equipo tiene abierto el puerto 9100. Se supone printer
 * *************************************************************************/
bool NMap::is_printer (QString ip){
    return nmap_is_open_port(ip,"9100");
}

/*******************************************************************************
 * Metodos auxiliares PRIVADOS a la clase para meter los datos en el struct
 * ****************************************************************************/

/**********************************readXML**************************************
 * Introduce en cada campo del struct los datos de QXmlStreamReader
 ******************************************************************************/
void NMap::readXML() {
       while(!reader.atEnd()) {
            reader.readNext();
            if (reader.isStartElement()) {
                  if (reader.name() == "nmaprun")
                          nmap_nmaprun();
                  else
                    if(reader.name() == "scaninfo")
                          nmap_scaninfo();
                  else
                    if(reader.name() == "verbose")
                          nmap_verbose();
                  else
                    if(reader.name() == "debuggin")
                          nmap_debuggin();
                  else
                    if(reader.name() == "host")
                          nmap_host();
                  else
                    if(reader.name() == "runstats")
                          nmap_runstats();
            }
         }
    }

void NMap::nmap_nmaprun(){
    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
        QString atributo = attr.name().toString();
        QString valor_tributo = attr.value().toString();
        if (atributo == "scanner" )
            nmapscan.nmaprun.scanner = valor_tributo;
        else
            if (atributo == "args" )
                nmapscan.nmaprun.args = valor_tributo;
            else
                if (atributo == "start" )
                    nmapscan.nmaprun.start = valor_tributo;
                else
                    if (atributo == "startstr" )
                        nmapscan.nmaprun.startstr = valor_tributo;
                    else
                        if (atributo == "version" )
                            nmapscan.nmaprun.version = valor_tributo;
                        else
                            if (atributo == "xmloutputversion" )
                                nmapscan.nmaprun.xmloutputversion = valor_tributo;

    }
}

void NMap::nmap_scaninfo() {
    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
        QString atributo = attr.name().toString();
        QString valor_tributo = attr.value().toString();
        if (atributo == "numservices" )
            nmapscan.scaninfo.numservices = atributo.toInt();
        else
            if (atributo == "protocol" )
                nmapscan.scaninfo.protocol = valor_tributo;
            else
                if (atributo == "services" )
                    nmapscan.scaninfo.services = valor_tributo;
                else
                    if (atributo == "type" )
                        nmapscan.scaninfo.type = valor_tributo;
    }
}

void NMap::nmap_verbose() {
    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
              QString atributo = attr.name().toString();
              QString valor_atributo = attr.value().toString();
              if (atributo == "level" )
                  nmapscan.debuggin.level = valor_atributo;
    }
}

void NMap::nmap_debuggin() {
    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
              QString atributo = attr.name().toString();
              QString valor_atributo = attr.value().toString();
              if (atributo == "level" )
                  nmapscan.debuggin.level = valor_atributo;
    }
}

void NMap::nmap_status(Host &host) {
    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
              QString atributo = attr.name().toString();
              QString valor_atributo = attr.value().toString();
              if (atributo == "state" )
                    host.status.state = valor_atributo;
              else
                if (atributo == "reason" )
                    host.status.reason  = valor_atributo;
              else
                if (atributo == "reason_ttl")
                    host.status.reason_ttl = valor_atributo;
    }
}

void NMap::nmap_address(Host &host) {
    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
              QString atributo = attr.name().toString();
              QString valor_atributo = attr.value().toString();
              if (atributo == "addr" )
                    host.address.addr  = valor_atributo;
              else
                if (atributo == "addrtype")
                    host.address.addrtype = valor_atributo;
    }
}

void NMap::nmap_hostnames(Host &host) {
    do{
      if (!reader.isEndElement()){
        if (reader.name()=="hostname")
            nmap_hostname(host);
      }
      if (!reader.atEnd())
            reader.readNext();
  }
  while (reader.name()!="hostnames");
}

void NMap::nmap_hostname(Host &host) {
    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
              QString atributo = attr.name().toString();
              QString valor_atributo = attr.value().toString();
              if (atributo == "name" )
                    host.hostnames.hostname.name = valor_atributo;
              else
                if (atributo == "type")
                    host.hostnames.hostname.type = valor_atributo;
    }
}

void NMap::nmap_host_host(Host &host) {
    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
          QString atributo = attr.name().toString();
          QString valor_atributo = attr.value().toString();
          if (atributo == "starttime" )
                  host.starttime = valor_atributo;
          else
              if (atributo == "endtime" )
                  host.endtime = valor_atributo;
    }
}

void NMap::nmap_hosts() {
    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
        QString atributo = attr.name().toString();
        QString valor_atributo = attr.value().toString();
        if (atributo == "up" )
            nmapscan.runstats.hosts.up = valor_atributo.toInt();
        else
            if (atributo == "down" )
                nmapscan.runstats.hosts.down = valor_atributo.toInt();
        else
            if (atributo == "total" )
                nmapscan.runstats.hosts.total = valor_atributo.toInt();

    }
}

void NMap::nmap_host() {
     Host host;

     do{
       if ((!reader.isEndElement()) && (reader.name()!="")){
          if (reader.name()=="host")
              nmap_host_host(host);
          else
              if (reader.name()=="status")
                  nmap_status(host);
          else
              if (reader.name()=="address")
                  nmap_address(host);
          else
              if (reader.name()=="hostnames")
                  nmap_hostnames(host);
          else
              if (reader.name()=="ports")
                  nmap_ports(host);
          else
              if (reader.name()=="os")
                  nmap_os(host);
          else
              if (reader.name()=="times")
                  nmap_times(host);
          else
              if (reader.name()=="uptime")
                  nmap_uptime(host);
          else
              if (reader.name()=="distance")
                  nmap_distance(host);
          else
              if (reader.name()=="tcpsecuence")
                  nmap_tcpsequence(host);
          else
              if (reader.name()=="ipidsequence")
                  nmap_ipidsequence(host);
          else
              if (reader.name()=="tcptssequence")
                  nmap_tcptssequence(host);
       }
       reader.readNext();

     }
     while (reader.name()!="host");
     nmapscan.host.append(host);
}

void NMap::nmap_ports(Host &host) {
    Port port;

      do{

          if (!reader.isEndElement()){
            if (reader.name()=="extraports")
                nmap_ports_extraports(host);
            else
                if (reader.name()=="extrareasons")
                    nmap_ports_extrareasons(host);
                else
                    if (reader.name()=="port"){
                        nmap_port(port);
                        host.ports.port.append(port);
                    }
          }
          if (!reader.atEnd())
                reader.readNext();
      }
      while (reader.name()!="ports");
}

void NMap::nmap_os(Host &host) {
 Portused portused;
 OSMatch osmatch;

         do{
            if (!reader.atEnd())
                reader.readNext();
            if ((!reader.isEndElement()) && (reader.name()!="")){
                if (reader.name()=="portused"){
                    nmap_os_portused(portused);
                    host.os.portused.append(portused);
                }
                else
                if (reader.name()=="osmatch"){
                    nmap_os_match(osmatch);
                    host.os.osmatch.append(osmatch);
                }
             }
         }
        while (reader.name()!="os");
}

void NMap::nmap_os_match(OSMatch &osmatch) {
    OSClass osclass;
    nmap_os_match_match(osmatch);
    do{
       if ((!reader.isEndElement()) && (reader.name()=="osclass"))
        {
             nmap_os_osclass(osclass);
             osmatch.osclass.append(osclass);
         }

         if (!reader.atEnd())
             reader.readNext();
    }
    while (reader.name()!="osmatch");
}

void NMap::nmap_os_match_match(OSMatch &osmatch) {

    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
             QString atributo = attr.name().toString();
             QString valor_atributo = attr.value().toString();
             if (atributo == "name")
                    osmatch.name = valor_atributo;
             else
                 if (atributo == "accuracy")
                    osmatch.accuracy = valor_atributo;
             else
                 if (atributo == "line")
                    osmatch.line = valor_atributo;
    }

}

void NMap::nmap_os_osclass_osclass(OSClass &osclass){
    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
             QString atributo = attr.name().toString();
             QString valor_atributo = attr.value().toString();
             if (atributo == "type")
                    osclass.type = valor_atributo;
             else
                 if (atributo == "vendor")
                    osclass.vendor = valor_atributo;
             else
                 if (atributo == "osfamily")
                    osclass.osfamily = valor_atributo;
             else
                 if (atributo == "osgen")
                    osclass.osgen = valor_atributo;
             else
                 if (atributo == "accuracy")
                    osclass.accuracy = valor_atributo;

     }
}

void NMap::nmap_os_osclass(OSClass &osclass){
nmap_os_osclass_osclass(osclass);

    do{
        if (!reader.atEnd())
            reader.readNext();
        if ((!reader.isEndElement()) && (reader.name()=="cpe"))
                nmap_os_cpe(osclass);
    }

    while (reader.name()!="osclass");
}

void NMap::nmap_os_cpe (OSClass &osclass){
    CPE cpe;
    cpe.cpe = reader.readElementText();
    osclass.cpe.append(cpe);
}

void NMap::nmap_os_portused(Portused &portused){

    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
              QString atributo = attr.name().toString();
              QString valor_atributo = attr.value().toString();
              if (atributo == "state")
                     portused.state = valor_atributo;
              else
                  if (atributo == "proto")
                     portused.proto = valor_atributo;
              else
                  if (atributo == "portid")
                     portused.portid = valor_atributo;

    }

}

void NMap::nmap_port(Port &port) {
    do{
        if (!reader.isEndElement()){
            if (reader.name()=="port")
                nmap_port_port(port);
            else
                if (reader.name()=="state")
                    nmap_port_state(port);
                else
                   if (reader.name()=="service")
                       nmap_port_service(port);
        }

        if (!reader.atEnd())
            reader.readNext();
    }
     while (reader.name()!="port");
}

void NMap::nmap_ports_extrareasons(Host &host){
    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
              QString atributo = attr.name().toString();
              QString valor_atributo = attr.value().toString();

              if (atributo == "reason")
                     host.ports.extrareasons.reason= valor_atributo;
              else
                  if (atributo == "count")
                     host.ports.extrareasons.count = valor_atributo;
    }
}

void NMap::nmap_ports_extraports(Host &host){
    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
              QString atributo = attr.name().toString();
              QString valor_atributo = attr.value().toString();

              if (atributo == "state")
                     host.ports.extraports.state= valor_atributo;
              else
                  if (atributo == "count")
                     host.ports.extraports.count = valor_atributo;
    }
}

void NMap::nmap_port_port(Port &port){
    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
              QString atributo = attr.name().toString();
              QString valor_atributo = attr.value().toString();

              if (atributo == "protocol")
                     port.protocol= valor_atributo;
              else
                  if (atributo == "portid")
                     port.portid = valor_atributo;
    }
}

void NMap::nmap_port_state(Port &port){
    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
              QString atributo = attr.name().toString();
              QString valor_atributo = attr.value().toString();
              if (atributo == "state")
                     port.state.state = valor_atributo;
              else
                  if (atributo == "reason")
                     port.state.reason = valor_atributo;
              else
                  if (atributo == "reason_ttl")
                     port.state.reason_ttl = valor_atributo;
    }
}

void NMap::nmap_uptime(Host &host){

        foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
                  QString atributo = attr.name().toString();
                  QString valor_atributo = attr.value().toString();
                  if (atributo == "seconds")
                         host.uptime.seconds = valor_atributo;
                  else
                      if (atributo == "lastboot")
                         host.uptime.lastboot = valor_atributo;
        }
}

void NMap::nmap_distance(Host &host){

        foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
                  QString atributo = attr.name().toString();
                  QString valor_atributo = attr.value().toString();
                  if (atributo == "value")
                         host.distance.value = valor_atributo;
        }
}

void NMap::nmap_tcpsequence(Host &host){

        foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
                  QString atributo = attr.name().toString();
                  QString valor_atributo = attr.value().toString();
                  if (atributo == "index")
                         host.tcpsequence.index = valor_atributo;
                  else
                      if (atributo == "difficulty")
                         host.tcpsequence.difficulty = valor_atributo;
                  else
                      if (atributo == "values")
                         host.tcpsequence.values = valor_atributo;
        }
}

void NMap::nmap_ipidsequence(Host &host){

        foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
                  QString atributo = attr.name().toString();
                  QString valor_atributo = attr.value().toString();
                  if (atributo == "class")
                         host.ipidsecuence.klass = valor_atributo;
                  else
                      if (atributo == "values")
                         host.ipidsecuence.values = valor_atributo;
        }
}

void NMap::nmap_tcptssequence(Host &host){

        foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
                  QString atributo = attr.name().toString();
                  QString valor_atributo = attr.value().toString();
                  if (atributo == "class")
                         host.tcptssequence.klass = valor_atributo;
                  else
                      if (atributo == "values")
                         host.tcptssequence.values = valor_atributo;
        }
}

void NMap::nmap_port_service(Port &port){
    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
              QString atributo = attr.name().toString();
              QString valor_atributo = attr.value().toString();
              if (atributo == "name")
                     port.service.name = valor_atributo;
              else
                  if (atributo == "method")
                     port.service.method = valor_atributo;
              else
                  if (atributo == "conf")
                     port.service.conf = valor_atributo;
     }
}

void NMap::nmap_times(Host &host) {
    foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
              QString atributo = attr.name().toString();
              QString valor_atributo = attr.value().toString();
              if (atributo == "srtt")
                     host.times.srtt = valor_atributo;
              else
                  if (atributo == "rttvar")
                     host.times.rttvar = valor_atributo;
              else
                  if (atributo == "to")
                     host.times.to = valor_atributo;
    }
}

void NMap::nmap_runstats() {

    do{
        if (reader.name()=="finished")
            nmap_finished();
        else
            if (reader.name()=="hosts")
                nmap_hosts();
        reader.readNext();
    }
    while (reader.name() != "runstats");

}

void NMap::nmap_finished(){

 foreach(const QXmlStreamAttribute &attr, reader.attributes()) {
    QString atributo = attr.name().toString();
    QString valor_atributo = attr.value().toString();
    if (atributo == "time" )
        nmapscan.runstats.time = valor_atributo;
    else
        if (atributo == "timestr" )
            nmapscan.runstats.timestr = valor_atributo;
    else
        if (atributo == "elapsed" )
            nmapscan.runstats.elapsed = valor_atributo;
    else
        if (atributo == "summary" )
            nmapscan.runstats.summary = valor_atributo;
    else
        if (atributo == "exit" )
            nmapscan.runstats.exit = valor_atributo;
  }
}


