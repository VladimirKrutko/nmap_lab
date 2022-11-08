import json
import nmap3
from os import popen
from typing import Dict, List
from transfrom_scan import TransformNmapScan


TRANSFORM = TransformNmapScan()


class NmapScan:

    def __init__(self) -> None:
        self.nmap = nmap3.Nmap()


    def nmap_sl_scan(self, host:str)->List:
        """
        This method realize nmap sl scan

        Args:
            host (str): host name or ip address

        Returns:
            List[dict, str]: dict - scan result, str-file name for decocarator
        """
        sl_result = self.nmap.nmap_list_scan(host)
        return sl_result


    def nmap_sn_scan(self, host:str):
        """
        This method realize nmap sn scan

        Args:
            host (str): host name or ip address

        Returns:
            List[dict, str]: dict - scan result, str-file name for decocarator
        """
        sn_result = popen(f'nmap -sn {host}').read()
        sn_data = TRANSFORM.transform_sn(sn_result)
        return sn_data
    

    def nmap_ss_scan(self, host:str, sudo_pass:str)-> List:
        """
        Function realise nmap ss scan 

        Args:
            host (str): host name or ip address
            sudo_pass: password to sudo agent
        Returns:
            Dict: scan result
        """
        ss_result = popen(f'echo {sudo_pass} | sudo -S nmap -sS {host}').read()
        ss_data = TRANSFORM.transform_ss(ss_string=ss_result)
        return ss_data
