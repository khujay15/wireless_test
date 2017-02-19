#include <vector>
#include <tins/tins.h>
#include <string>
#include <algorithm>
#include <iostream>
#include <pthread.h>
using namespace Tins;


class apinfo{
public:
    int power;
    int beacon=0;
    std::string bssid;
    int channel;
    std::string essid;
    int data=0;
};

class station{
public:
    std::string bssid;
    std::string mac;
    std::string probe;

};


void beacon_plus(std::string mac,std::vector<apinfo>& apVector )
{

    for(std::vector<apinfo>::iterator it=apVector.begin();it!=apVector.end();it++)
    {
        if(it->bssid ==mac)
        {
            it->beacon=it->beacon+1;
        }
    }


}


void data_plus(std::string mac,std::vector<apinfo>& apVector )
{

    for(std::vector<apinfo>::iterator it=apVector.begin();it!=apVector.end();it++)
    {
        if(it->bssid ==mac)
        {
            it->data=it->data+1;
        }
    }


}

std::vector<Packet> vt;
bool sniffing=true;
pthread_mutex_t  mutex = PTHREAD_MUTEX_INITIALIZER;


void* sniff(void* data)
{
    while(sniffing)
    {
        Sniffer sniffer("mon0");

        sniffer.set_filter("type Radiotap");

        pthread_mutex_lock(&mutex);
        vt.push_back(sniffer.next_packet());
        pthread_mutex_unlock(&mutex);
    }
}
PDU* pdu;

int main() {

    pthread_t p_thread1;
    int thr_id;
//    thr_id=pthread_create(&p_thread1,NULL,sniff,NULL);

    std::vector<std::string> essid;
    std::vector<std::string> bssid;
    std::vector<std::string>::iterator strit;
    std::vector<std::string> stationMac;


    std::vector<apinfo> apVector;
    std::vector<station> stationVector;


    std::vector<Packet>::iterator it=vt.begin();

    while(vt.size() < 10)
    {
        Sniffer sniffer("mon0");
      //  sniffer.set_filter("type mgt");
        vt.push_back(sniffer.next_packet());
    }

    int i=0;
    for(it=vt.begin();it!=vt.end();it++)
    {
        Sniffer sniffer("mon0");
      //  sniffer.set_filter("type mgt");
        vt.push_back(sniffer.next_packet());
        pdu = vt[i].pdu();
        i++;

        RadioTap* temp = pdu->find_pdu<RadioTap>();
        if (temp == nullptr)
        {

           pdu= vt[i+1].pdu();
            continue;
        }




        Dot11ManagementFrame* dot11 = (Dot11ManagementFrame*)temp->find_pdu<Dot11ManagementFrame>();
        if( dot11 != nullptr)
        {
            auto subtype = dot11->subtype();
        std::string strtemp=dot11->addr2().to_string();


        if(!strtemp.empty())
        std::cout<< dot11->ssid() <<std::endl;
        else
           std::cout<<"empty ssid"<<std::endl;

        std::cout<< dot11->addr1() <<std::endl;
        std::cout<< dot11->addr2() <<std::endl;
        std::cout<< dot11->addr3() <<std::endl;
        std::cout<< dot11->addr4() <<std::endl;

        std::cout<< std::endl;

        beacon_plus(dot11->addr2().to_string(),apVector);

        strit= find(bssid.begin(),bssid.end(),strtemp);
        if(strit == bssid.end())
        {
            bssid.push_back(strtemp);
            apinfo ap;
            ap.bssid=dot11->addr2().to_string();
            ap.channel=temp->channel_freq() % 2412 / 5 + 1;
            auto tempssid= dot11->ssid();
                if(!tempssid.empty())
                    ap.essid=dot11->ssid();
                else
                    ap.essid="empty";
            ap.power =temp->dbm_signal();
            apVector.push_back(ap);
        }
            if(subtype == Dot11::PROBE_REQ)
            {
                Dot11ProbeRequest* p_req = (Dot11ProbeRequest*)dot11->find_pdu<Dot11ProbeRequest>();
                std::cout<<"#" <<p_req->addr1() <<std::endl;
                std::cout<<"#" <<p_req->addr2() <<std::endl;
                std::cout<<"#" <<p_req->addr3() <<std::endl;
                std::cout<<"#" <<p_req->addr4() <<std::endl;


            }
            else if(subtype == Dot11::PROBE_RESP)
            {
                Dot11ProbeResponse* p_resp = (Dot11ProbeResponse*)dot11->find_pdu<Dot11ProbeResponse>();
                std::cout<<"@" <<p_resp->addr1() <<std::endl;
                std::cout<<"@" <<p_resp->addr2() <<std::endl;
                std::cout<<"@" <<p_resp->addr3() <<std::endl;
                std::cout<<"@" <<p_resp->addr4() <<std::endl;

            }
        }
        else
        {
            Dot11Data* dot11data = (Dot11Data*)temp->find_pdu<Dot11Data>();
            if(dot11data == nullptr)
                continue;

            std::string apmac=dot11data->addr2().to_string();
            std::string stationmac=dot11data->addr1().to_string();

            data_plus(dot11data->addr2().to_string(),apVector);


            strit= find(bssid.begin(),bssid.end(),apmac);
            if(strit == bssid.end())
            {
                bssid.push_back(apmac);
                apinfo ap;
                ap.bssid=apmac;
                ap.channel=temp->channel_freq() % 2412 / 5 + 1;
                ap.essid=dot11->ssid();
                ap.power =temp->dbm_signal();
                apVector.push_back(ap);
            }

            std::vector<std::string>::iterator stat= find(stationMac.begin(),stationMac.end(),stationmac);
            if(stat == stationMac.end())
            {
                station sta;
                sta.bssid=apmac;
                sta.mac=stationmac;

                stationVector.push_back(sta);
            }


            std::cout<< dot11data->addr1() <<std::endl;//station
            std::cout<< dot11data->addr2() <<std::endl;//ap
        }

        std::cout <<std::endl;

//        pthread_mutex_lock(&mutex);
//        vt.erase(it);
//        pthread_mutex_unlock(&mutex);

    }
    int status;
//    pthread_join(p_thread1, (void **)&status);
    return 0;


}
