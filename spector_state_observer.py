# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024–present
# See LICENSE for details.

import xml.etree.ElementTree as ET
import os
import logging
import psutil
import socket
import threading
import tempfile

logging.basicConfig(level=logging.INFO)

CLIENT_STATS_XML = "/etc/opensiem/stats/ClientStats.xml"

file_lock = threading.Lock()

def create_client_stats_xml():
    dir_path = os.path.dirname(CLIENT_STATS_XML)
    os.makedirs(dir_path, exist_ok=True)
    os.chmod(dir_path, 0o755)
    if not os.path.exists(CLIENT_STATS_XML):
        root = ET.Element("ClientStatistics")
        tree = ET.ElementTree(root)
        tree.write(CLIENT_STATS_XML, encoding='unicode')
        os.chmod(CLIENT_STATS_XML, 0o644)

def process_stats(xml_data):
    try:
        ET.fromstring(xml_data)
        return True
    except ET.ParseError:
        logging.error("Invalid XML format received.")
        return False
    
def update_client_stats_xml(system_id, given_name, cpu_total, cpu_cores,
                            ram_attribs, disk_attribs, service_stats):

    if not os.path.exists(CLIENT_STATS_XML):
        root = ET.Element("ClientStatistics")
        tree = ET.ElementTree(root)
        tree.write(CLIENT_STATS_XML, encoding='unicode')
    try:
        tree = ET.parse(CLIENT_STATS_XML)
        root = tree.getroot()
    except ET.ParseError:
        root = ET.Element("ClientStatistics")
        tree = ET.ElementTree(root)

    system_element = root.find(f"./System[@ID='{system_id}']")
    if system_element is None:
        system_element = ET.SubElement(root, "System")
        system_element.set("ID", system_id)

    if given_name:
        system_element.set("GivenName", given_name)

    cpu_element = system_element.find("CPUUsage")
    if cpu_element is not None:
        system_element.remove(cpu_element)
    cpu_element = ET.SubElement(system_element, "CPUUsage")
    if cpu_total is not None:
        cpu_element.set("Total", str(cpu_total))
    for core_tag, core_val in (cpu_cores or {}).items():
        c = ET.SubElement(cpu_element, core_tag)
        c.text = str(core_val)

    ram_element = system_element.find("RAMUsage")
    if ram_element is not None:
        system_element.remove(ram_element)
    ram_element = ET.SubElement(system_element, "RAMUsage")
    for k, v in (ram_attribs or {}).items():
        ram_element.set(k, str(v))

    disk_element = system_element.find("DiskUsage")
    if disk_element is not None:
        system_element.remove(disk_element)
    disk_element = ET.SubElement(system_element, "DiskUsage")
    for k, v in (disk_attribs or {}).items():
        disk_element.set(k, str(v))

    services_element = system_element.find("ServiceStatus")
    if services_element is not None:
        system_element.remove(services_element)
    services_element = ET.SubElement(system_element, "ServiceStatus")
    for service_name, service_status in (service_stats or {}).items():
        service_element = ET.SubElement(services_element, "Service")
        service_element.set("Name", service_name)
        service_element.set("Status", str(service_status))

    fd, tmp_path = tempfile.mkstemp(prefix='ClientStats.', suffix='.xml',
                                    dir=os.path.dirname(CLIENT_STATS_XML))
    os.close(fd)
    try:
        tree.write(tmp_path, encoding='unicode')
        os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, CLIENT_STATS_XML)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass

def start_server():
    server_ip = '0.0.0.0'
    server_port = 51780

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((server_ip, server_port))
    server_socket.listen(128)

    logging.info(f"Server listening on {server_ip}:{server_port}")

    while True:
        client_socket, client_address = server_socket.accept()

        try:
            message = client_socket.recv(4096).decode('utf-8')
            logging.debug(f"[Received Log from {client_address}]: {message}")
            
            if message.startswith("<SystemStats>"):
                if not process_stats(message):
                    logging.error("Received malformed SystemStats message from %s", client_address)
                try:
                    root = ET.fromstring(message)
                    system_el = root.find(".//System")
                    if system_el is None:
                        raise ValueError("No System element in SystemStats")

                    system_id = system_el.get("ID")
                    given_name = system_el.get("GivenName", "")

                    cpu_elem = system_el.find("CPUUsage")
                    cpu_total = None
                    cpu_cores = {}
                    if cpu_elem is not None:
                        cpu_total = cpu_elem.attrib.get("Total")
                        for child in list(cpu_elem):
                            tag = child.tag  # e.g. Core0
                            text = (child.text or "").strip()
                            cpu_cores[tag] = text

                    ram_elem = system_el.find("RAMUsage")
                    ram_attribs = ram_elem.attrib if ram_elem is not None else {}

                    disk_elem = system_el.find("DiskUsage")
                    disk_attribs = disk_elem.attrib if disk_elem is not None else {}

                    services_element = system_el.find('ServiceStatus')
                    service_stats = {}
                    if services_element is not None:
                        for service_element in services_element.findall("Service"):
                            service_name = service_element.get("Name")
                            service_status = service_element.get("Status") or (service_element.text or "")
                            service_stats[service_name] = service_status

                    with file_lock:
                        update_client_stats_xml(system_id, given_name, cpu_total, cpu_cores,
                                                ram_attribs, disk_attribs, service_stats)
                except Exception as e:
                    logging.error(f"Error updating ClientStats.xml: {e}")
            else:
                logging.error("Invalid log format received")
                
        except Exception as e:
            logging.error(f"Error processing message: {e}")

        client_socket.close()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    create_client_stats_xml()
    # start_server()
    server_thread = threading.Thread(target=start_server)
    server_thread.daemon = True
    server_thread.start()
    server_thread.join()
