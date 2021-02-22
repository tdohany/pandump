#!/usr/bin/env python

# secdump - A utility to dump PAN-OS security rulebases into comma-delimited output

__author__ = "Robert Hagen (@stealthllama)"
__copyright__ = "Copyright 2018, Palo Alto Networks"
__version__ = "0.1"
__license__ = "GPL"
__status__ = "Development"


from pan.xapi import *
import xml.etree.ElementTree as eT
import argparse
import getpass

SECURITY_RULES_XPATH = "./devices/entry[@name='localhost.localdomain']" \
                       "/vsys/entry[@name='vsys1']/rulebase/security/rules"
DEFAULT_SECURITY_RULES_XPATH = "./predefined/default-security-rules"
PRE_RULEBASE_XPATH = "panorama/pre-rulebase/security/rules"
POST_RULEBASE_XPATH = "panorama/post-rulebase/security/rules"


def open_file(filename):
    try:
        outfilehandle = open(filename, 'w')
        return outfilehandle
    except IOError:
        print("Error: Cannot open file %s" % filename)


def make_parser():
    # Parse the arguments
    parser = argparse.ArgumentParser(description="Export security rules from a Palo Alto Networks firewall")
    parser.add_argument("-u", "--username", help="administrator username")
    parser.add_argument("-p", "--password", help="administrator password", default='')
    parser.add_argument("-f", "--firewall", help="firewall address")
    parser.add_argument("-t", "--tag", help="firewall tag from the .panrc file", default='')
    parser.add_argument("-o", "--outfile", help="output file", default='')
    parser.add_argument("-i", "--infile", help="input file, no API used when provided", default='')
    args = parser.parse_args()
    if args.password == '' and args.infile == '':
        args.password = getpass.getpass()
    return args


def get_local_tree(this_input_parameters):
    if isinstance(this_input_parameters, PanXapi):
        this_input_parameters.get(xpath=SECURITY_RULES_XPATH)
        tree = eT.fromstring(this_input_parameters.xml_result())
    else:
        tree = eT.parse(this_input_parameters).find(SECURITY_RULES_XPATH)
    return tree


def get_shared_tree(this_input_parameters):
    if isinstance(this_input_parameters, PanXapi):
        this_input_parameters.op(cmd="<show><config><pushed-shared-policy></pushed-shared-policy></config></show>")
        tree = eT.fromstring(this_input_parameters.xml_result())
    else:
        tree = eT.parse(this_input_parameters)
    if tree is not bytes:
        prerules = tree.find(PRE_RULEBASE_XPATH)
        postrules = tree.find(POST_RULEBASE_XPATH)
        return prerules, postrules
    else:
        return tree


def get_predefined_tree(this_input_parameters):
    if isinstance(this_input_parameters, PanXapi):
        this_input_parameters.get(xpath=DEFAULT_SECURITY_RULES_XPATH)
        tree = eT.fromstring(this_input_parameters.xml_result())
    else:
        tree = eT.parse(this_input_parameters).find(DEFAULT_SECURITY_RULES_XPATH)
    return tree

def write_security_header(thisfile):
    thisfile.write(
        'No,Name,Source Zone,Source Address,Source User,Source HIP Profile,Destination Zone,Destination Address,'
        'Application,Service,URL Category,Action,Profile,Options,Description,Type,Tags,Disabled\n')


def format_members(thislist):
    outlist = ";".join(str(x) for x in thislist)
    return outlist


def write_security_rule(rule, outputfile, rulecount, ruletype):
    #
    # Process the rule
    #

    # Get the rule name
    rule_name = rule.get('name')

    # Get the from_zone members
    from_zone = []
    for from_iter in rule.iterfind('from/member'):
        from_zone.append(from_iter.text)

    # Get the to_zone members
    to_zone = []
    for to_iter in rule.iterfind('to/member'):
        to_zone.append(to_iter.text)

    # Get the source address members
    source = []
    for source_iter in rule.iterfind('source/member'):
        source.append(source_iter.text)

    # Get the destination address members
    destination = []
    for dest_iter in rule.iterfind('destination/member'):
        destination.append(dest_iter.text)

    # Get the source user members
    user = []
    for user_iter in rule.iterfind('source-user/member'):
        user.append(user_iter.text)

    # Get the HIP profile members
    hip = []
    for hip_iter in rule.iterfind('hip-profiles/member'):
        hip.append(hip_iter.text)

    # Get the URL category members
    category = []
    for category_iter in rule.iterfind('category/member'):
        category.append(category_iter.text)

    # Get the application members
    application = []
    for application_iter in rule.iterfind('application/member'):
        application.append(application_iter.text)

    # Get the service members
    service = []
    for service_iter in rule.iterfind('service/member'):
        service.append(service_iter.text)

    # Get the action
    action = rule.find('action')

    # Get the log setting
    log_setting = rule.find('log-setting')

    # Get the description
    description = rule.find('description')

    # Get the tag members
    tag = []
    for tag_iter in rule.iterfind('tag/member'):
        tag.append(tag_iter.text)

    # Get the disabled state
    disabled_state = rule.find('disabled')

    # Get the profiles or profile group
    av_profile = []
    vuln_profile = []
    spyware_profile = []
    url_profile = []
    data_profile = []
    file_profile = []
    wildfire_profile = []
    profile_group = []
    if rule.find('profile-setting/group'):
        profile_group = rule.find('profile-setting/group/member')
    elif rule.find('profile-setting/profiles'):
        av_profile = rule.find('profile-setting/profiles/virus/member')
        vuln_profile = rule.find('profile-setting/profiles/vulnerability/member')
        spyware_profile = rule.find('profile-setting/profiles/spyware/member')
        url_profile = rule.find('profile-setting/profiles/url-filtering/member')
        data_profile = rule.find('profile-setting/profiles/data-filtering/member')
        file_profile = rule.find('profile-setting/profiles/file-blocking/member')
        wildfire_profile = rule.find('profile-setting/profiles/wildfire-analysis/member')

    #
    # Let's write the rule
    #

    # Write the rule count
    outputfile.write(str(rulecount) + ',')

    # Write the rule name
    outputfile.write(rule_name + ',')

    # Write the from_zone members
    if ruletype != 'default':
        outputfile.write(format_members(from_zone) + ',')
    else:
        outputfile.write('any' + ',')

    # Write the source members
    if ruletype != 'default':
        outputfile.write(format_members(source) + ',')
    else:
        outputfile.write('any' + ',')

    # Write the user members
    if ruletype != 'default':
        outputfile.write(format_members(user) + ',')
    else:
        outputfile.write('any' + ',')

    # Write the HIP profile members
    if ruletype != 'default':
        outputfile.write(format_members(hip) + ',')
    else:
        outputfile.write('any' + ',')

    # Write the to_zone members
    if ruletype != 'default':
        outputfile.write(format_members(to_zone) + ',')
    elif rule_name == 'intrazone-default':
        outputfile.write('(intrazone)' + ',')
    else:
        outputfile.write('any' + ',')

    # Write the destination members
    if ruletype != 'default':
        outputfile.write(format_members(destination) + ',')
    else:
        outputfile.write('any' + ',')

    # Write the application members
    if ruletype != 'default':
        outputfile.write(format_members(application) + ',')
    else:
        outputfile.write('any' + ',')

    # Write the service members
    if ruletype != 'default':
        outputfile.write(format_members(service) + ',')
    else:
        outputfile.write('any' + ',')

    # Write the category members
    if ruletype != 'default':
        outputfile.write(format_members(category) + ',')
    else:
        outputfile.write('any' + ',')

    # Write the action
    outputfile.write(action.text + ',')

    # Write the profile or group
    if rule.find('profile-setting/group'):
        outputfile.write(profile_group.text)
    elif rule.find('profile-setting/profiles'):
        profile_list = []
        if av_profile is not None:
            profile_list.append('Antivirus: ' + av_profile.text)
        if vuln_profile is not None:
            profile_list.append('Anti-Spyware: ' + vuln_profile.text)
        if spyware_profile is not None:
            profile_list.append('Vulnerability Protection: ' + spyware_profile.text)
        if url_profile is not None:
            profile_list.append('URL Filtering: ' + url_profile.text)
        if data_profile is not None:
            profile_list.append('Data Filtering: ' + data_profile.text)
        if file_profile is not None:
            profile_list.append('File Blocking: ' + file_profile.text)
        if wildfire_profile is not None:
            profile_list.append('WildFire Analysis: ' + wildfire_profile.text)
        outputfile.write(format_members(profile_list))
    else:
        outputfile.write('none')
    outputfile.write(',')

    # Write the log forwarding profile (if defined)
    if log_setting is None:
        outputfile.write('none,')
    else:
        outputfile.write(log_setting.text + ',')

    # Write the description (if defined)
    if description is None:
        outputfile.write('none,')
    else:
        outputfile.write(description.text)

    # Write the rule type
    outputfile.write(ruletype + ',')

    # Write the tag members (if defined)
    if len(tag) == 0:
        outputfile.write('none,')
    else:
        outputfile.write(format_members(tag) + ',')

    # Write the Disabled status (if defined)
    if disabled_state is None:
        outputfile.write('none,')
    else:
        outputfile.write(disabled_state.text + ',')

    # Finish it!
    outputfile.write('\n')


def main():
    # Grab the args
    myargs = make_parser()
    if myargs.infile == '':
        # Open a firewall API connection
        if myargs.tag:
            # Use the .panrc API key
            my_input_parameters = PanXapi(tag=myargs.tag)
        else:
            # Generate the API key
            my_input_parameters = PanXapi(api_username=myargs.username, api_password=myargs.password, hostname=myargs.firewall)
    else:
        my_input_parameters = myargs.infile
        # Try to open the input file
        try:
            with open(my_input_parameters) as f:
                pass
        except IOError:
            print("Input file not accessible.")
            exit(1)


    # Open the output file
    if myargs.outfile:
        outfile = open_file(myargs.outfile)
    else:
        outfile = sys.stdout


    # Grab the local rulebase XML tree
    localtree = get_local_tree(my_input_parameters)

    # Grab the shared rulebase XML tree
    sharedtree = get_shared_tree(my_input_parameters)

    # Grab the predfined rulebase XML tree
    predefinedtree = get_predefined_tree(my_input_parameters)

    # Write the HTML table
    write_security_header(outfile)

    # Process all the security rules

    count = 1
    rule_type = ''

    # Process the pre-rules rules
    if sharedtree is not None and sharedtree[0]:
        for prerule in sharedtree[0].iter('entry'):
            rule_type = 'pre'
            write_security_rule(prerule, outfile, count, rule_type)
            count += 1

    # Process the local security rules
    if localtree is not None:
        for rule in localtree.iter('entry'):
            rule_type = 'local'
            write_security_rule(rule, outfile, count, rule_type)
            count += 1

    # Process the post-rules
    if sharedtree is not None and sharedtree[1]:
        for postrule in sharedtree[1].iter('entry'):
            rule_type = 'post'
            write_security_rule(postrule, outfile, count, rule_type)
            count += 1

    # Process the predefined rules
    if predefinedtree is not None:
        for predefinedrule in predefinedtree.iter('entry'):
            rule_type = 'default'
            write_security_rule(predefinedrule, outfile, count, rule_type)
            count += 1

    # Close the output file
    if outfile is not sys.stdout:
        outfile.close()


if __name__ == '__main__':
    main()
