from typing import List, Dict


class TransformNmapScan:

    @staticmethod
    def transform_sn(sn_string:str)-> Dict:
        sn_list = sn_string.split('\n')
        if not sn_list[0]:
            sn_list = sn_list[1:]
        res_scan = [sn_list[i-1:i+1] for i in range(1, len(sn_list), 2)]
        res_data = dict()
        for obj in res_scan[1:-1]:

            if 'Nmap' in obj[-1]:
                obj.reverse()

            host_ip = obj[0].split(' ')
            ip = host_ip[-1][0:-1]
            host = host_ip[-2] if host_ip[-2] != 'for' else ''
            ping = obj[1].split()[-2][1:-1]
            res_data[ip] = {
                'host': host,
                'ping': ping
            }
        return res_data


    @staticmethod
    def transform_sl(sl_string:str)-> List:
        """
        Function transofrm sl scan result to list

        Args:
            sl_string (str): sl scan result in string format

        Returns:
            List[List]: list with scan result, that contain ip and host
        """
        sl_list = sl_string.split('\n')
        sl_res = list( map(lambda x: [x.split()[-1][1:-1], ''] 
                            if x.split()[-2] == 'for' 
                            else  
                            [x.split()[-1][1:-1], x.split()[-2]],sl_list[2:-2]))
        return sl_res

    
    @staticmethod
    def transform_ss(ss_string: str)->Dict:
        """
        Function transform ss scan result

        Args:
            ss_string (str): ss scan result in string format 

        Returns:
            Dict: dict with information about scan
        """
        ss_data = ss_string.split('Nmap scan report for ')
        res_data = dict()
        for ss in ss_data[1:]:
            test_ss = ss.split('\n')
            host_ip = test_ss[0].split()
            host, ip = host_ip[0], host_ip[-1][1:-1]
            latency = test_ss[1].split()[-2][1:-1]
            port_data = dict()
            ports = test_ss[4:]
            ind = 0
            while ports[ind]:
                port_inf = ports[ind].split()
                port = port_inf[0]
                status = port_inf[1]
                service = port_inf[2]
                ind+=1
                port_data[port] = {'status': status, 'service': service}
            res_data[ip] = {
                'host': host,
                'ping': latency,
                'ports': port_data
            }
        return res_data
