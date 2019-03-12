#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import glob
import itertools
import lxml.etree as ET


def pa_obj_parser(xml):
    """
    Retrieves all (shared) objects from a Palo Alto configuration file

    :param xml: ElementTree of the configuration file(s)
    :return: Dicts of service, address, service-group and address-group objects
    """

    pa_services, pa_addresses, pa_service_groups, pa_address_groups = ({} for i in range(4))

    # Retrieve objects by XPath
    services = tree.xpath(".//service/entry[@name]/protocol/*/port")
    addresses = tree.xpath(".//address/entry[@name]/ip-netmask")
    service_groups = tree.xpath(".//service-group/entry[@name]/members[member]")
    address_groups = tree.xpath(".//address-group/entry[@name]/static[member]")

    for s in services:
        service_name = s.getparent().getparent().getparent().values()[0]
        port_range = ''.join(s.itertext())
        if port_range == '1-65535':
            port_range = 'any'
        # Format services as <protocol>_<range>
        service_type = s.getparent().tag + '_' + port_range
        # Create a mapping of each service_name to service_type
        pa_services[str(service_name)] = service_type

    for a in addresses:
        pa_addresses[a.getparent().values()[0]] = ''.join(a.itertext()).split()

    for sg in service_groups:
        pa_service_groups[sg.getparent().values()[0]] = ''.join(sg.itertext()).split()

    for ag in address_groups:
        pa_address_groups[ag.getparent().values()[0]] = ''.join(ag.itertext()).split()

    return pa_services, pa_addresses, pa_service_groups, pa_address_groups


def pa_rule_parser(xml):
    """
    Retrieves all rules from a Palo Alto configuration file and formats each rule
    to a list with (in sequence): 'fw_name, rule_name, source, port, destination'

    :param xml: ElementTree of the configuration file(s)
    :return: Two-dimensional list of rules following the described format
    """

    pan_conf = None  # Toggle between Panorama and device configuration files
    pa_rule_base = []

    # Retrieve the ancestor of each rulebase
    if tree.xpath("/config/panorama"):
        # Panorama parser
        pan_conf = True
        pa_rulebase_ancestor = list(tree.xpath(".//entry[@name]/devices/entry[@name]/vsys/entry/"
                                               "@name/ancestor::entry[position()=3]/@name"))
    else:
        # Multi-vsys parser
        pa_vsys_name = tree.xpath(".//entry[contains(@name,'vsys')]/display-name/text()")
        pa_rulebase_ancestor = []
        for vsys in pa_vsys_name:
            pa_rulebase_ancestor.append(''.join(vsys.getparent().getparent().attrib['name']))

    for ancestor in pa_rulebase_ancestor:
        vsys_rule_src = tree.xpath("//entry[@name='{}']/*[contains(local-name(), 'rulebase')]"
                                   "/security/rules/entry[@name]/*[self::source[member]]".format(ancestor))
        vsys_rule_dst = tree.xpath("//entry[@name='{}']/*[contains(local-name(), 'rulebase')]"
                                   "/security/rules/entry[@name]/*[self::destination[member]]".format(ancestor))
        vsys_rule_port = tree.xpath("//entry[@name='{}']/*[contains(local-name(), 'rulebase')]"
                                    "/security/rules/entry[@name]/*[self::service[member]]".format(ancestor))
        if pan_conf:
            pa_vsys_name = ancestor + '-pan'
        else:
            pa_vsys_name = tree.xpath("//entry[@name='{}']/display-name/text()".format(ancestor))

        for src, dst, port in zip(vsys_rule_src, vsys_rule_dst, vsys_rule_port):
            pa_rule_id = src.getparent().values()[0]
            pa_rule_src = ';'.join(''.join(src.itertext()).split())
            pa_rule_dst = ';'.join(''.join(dst.itertext()).split())
            pa_rule_port = ';'.join(''.join(port.itertext()).split())
            pa_rule_base.append([''.join(pa_vsys_name), pa_rule_id, pa_rule_src, pa_rule_port, pa_rule_dst])

    return pa_rule_base

if __name__ == '__main__':
    # Parse all device configuration files plus the Panorama configuration file
    rule_base = []
    conf_path = glob.glob("pa_configs/*.xml")
    for conf in conf_path:
        tree = ET.parse(conf)

        # Retrieve all objects
        services, addresses, service_groups, address_groups = pa_obj_parser(tree)
        # Retrieve all rules
        device_rules = pa_rule_parser(tree)
        rule_base.append(device_rules)

    # Retain only unique rules in the rulebase
    flat_rule_base = list(itertools.chain(*rule_base))
    flat_rule_base_unique = set(tuple(row) for row in flat_rule_base)

    # Write the rulebase
    with open("pa_rule_db.csv", "w", newline="\n", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerows(set(flat_rule_base_unique))
