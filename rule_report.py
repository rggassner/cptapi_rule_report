#!/usr/bin/python3
# -*- coding: utf-8 -*-
import sys
from cptapi import Cptapi
import re
import os
from my_config import *
from translations import translations
report_dir="output"
from datetime import datetime

show_groups=True
show_generic=True
packet_mode=True
generic_objs=['network-010-000-000-000_8','Any']

targets_destination=[
    {'rulebase' : '', 'network' : '1.1.1.', 'start' : 1, 'end' : 1},
    ]

# Translation helper
def T(key):
    return translations[LANG][key]

def get_objlst(rule,query,param):
    rstr=[]
    for obj in rule[param]:
        rstr.append(get_uid(query['objects-dictionary'],obj)['name'])
    return rstr

def get_param(obj,param):
    if param in obj:
        return obj[param]
    else:
        return '---'

def get_uid(listobj,uid):
    return list(filter(lambda x: 'uid' in x and x['uid']==uid,listobj))[0]

def report(target,query,domain,layer,rules,rtype,host_names):
    if not 'rulebase' in query:
        print (T("rulebase_not_found").format(domain,layer))
        return rules
    sections=query['rulebase']
    if not isinstance(sections,list):
        sections=[sections]
    for section in sections:
        if section['type'] == 'access-section':
            for rule in section['rulebase']:
                rules=print_rule(rule,query,section['name'],domain,layer,rules,rtype,host_names)
        elif section['type'] == 'access-rule':
            rules=print_rule(section,query,T("empty_section"),domain,layer,rules,rtype,host_names)
        else:
                print(T("unknown_error"))
    return rules

def is_generic(rule_objects):
    for obj in rule_objects:
        if obj in generic_objs:
            return True
    return False

def is_address_specific(rule_objects,address_names):
    for obj in rule_objects:
        if obj in address_names:
            return True
    return False

def print_rule(rule,query,section,domain,layer,rules,rtype,host_names):
    row_color=''
    status=''
    if get_param(rule,'enabled'):
        status=T("rule_enabled")
    else:
        status=T("rule_disabled")
        row_color='bgcolor=\"#d3d3d3\"'
    snegate=''
    if get_param(rule,'source-negate'):
        snegate=T("negated")
    dnegate=''
    if get_param(rule,'destination-negate'):
        dnegate=T("negated")
    srvnegate=''
    if get_param(rule,'service-negate'):
        srvnegate=T("negated")
    action=get_uid(query['objects-dictionary'],get_param(rule,'action'))['name']
    fmt_rule='<tr {}><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n'.format(row_color,domain,layer,section,get_param(rule,'rule-number'),status,get_param(rule,'name'),
        snegate+' '.join([str(item) for item in get_objlst(rule,query,'source')]),
        dnegate+' '.join([str(item) for item in get_objlst(rule,query,'destination')]),
        srvnegate+' '.join([str(item) for item in get_objlst(rule,query,'service')]),
        action,get_param(rule,'comments'))
    if get_param(rule,'enabled'):
        if (is_address_specific(get_objlst(rule,query,'destination'),host_names) and rtype == 'd-') or (is_address_specific(get_objlst(rule,query,'source'),host_names) and rtype == 's-'):
            rules[rtype+'address']=rules[rtype+'address']+fmt_rule
        elif is_generic(get_objlst(rule,query,'destination')) or is_generic(get_objlst(rule,query,'source')):
            rules[rtype+'generic']=rules[rtype+'generic']+fmt_rule
        else:
            rules[rtype+'group']=rules[rtype+'group']+fmt_rule
    return rules

def get_host_names(ip_address):
    names=this_domain.show_objects(object_type='host',ip_only=True,object_filter=ip_address)
    result=[i['name'] for i in names['objects']]
    return result

def create_report_directory():
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)

def write_ouput_report(target,rules):
    f=open(report_dir+'/'+target+'.html','w')
    now=datetime.now()
    f.write('<meta http-equiv="Content-type" content="text/html; charset=utf-8" />\n')
    f.write('<body>{}<br>\n'.format(now.strftime("%d/%m/%Y, %H:%M:%S")))
    f.write('<br><b>{}</b><br><br>{}<br><br><br><br>'.format(
        T("report_title"), T("disclaimer"))
    )
    f.write('<h1>{}</h1>\n'.format(T("specific_dst").format(target)))
    f.write(T("table_header"))
    f.write(rules['d-address'])
    f.write('</table>\n')
    f.write('<h1>{}</h1>\n'.format(T("specific_src").format(target)))
    f.write(T("table_header"))
    f.write(rules['s-address'])
    f.write('</table>\n')
    if show_groups:
        f.write('<h1>{}</h1>\n'.format(T("group_dst").format(target)))
        f.write(T("table_header"))
        f.write(rules['d-group'])
        f.write('</table>\n')
        f.write('<h1>{}</h1>\n'.format(T("group_src").format(target)))
        f.write(T("table_header"))
        f.write(rules['s-group'])
        f.write('</table>\n')
        if show_generic:
            f.write('<h1>{}</h1>\n'.format(T("generic")))
            f.write(T("table_header"))
            f.write(rules['d-generic'])
            f.write('</table>\n')
    f.write('</body>\n')
    f.close()

create_report_directory()
mds=Cptapi(user,password,url,'MDS',api_wait_time=api_wait_time,read_only=True,page_size=page_size)
domains=mds.show_domains()
mds.logout()
for nw in targets_destination:
    for counter in range(nw['start'],nw['end']+1):
        rules={'d-address':'','d-group':'','d-generic':'','s-address':'','s-group':'','s-generic':''}
        target=nw['network']+str(counter)
        print('Working on target {}'.format(target))
        for domain in domains:
            this_domain=Cptapi(user,password,url,domain['name'],api_wait_time=api_wait_time,read_only=False,page_size=page_size)
            print('Domain {}'.format(domain['name']))
            host_names=get_host_names(target)
            layers=this_domain.show_acess_layers()
            for layer in layers:
                print('Layer    "{}"'.format(layer['name']))
                query=this_domain.show_access_rulebase(name=layer['name'],dst=target,packet=packet_mode)
                rules=report(target,query,domain['name'],layer['name'],rules,'d-',host_names)
                query=this_domain.show_access_rulebase(name=layer['name'],src=target,packet=packet_mode)
                rules=report(target,query,domain['name'],layer['name'],rules,'s-',host_names)
            this_domain.logout()
        write_ouput_report(target,rules)
