import sys
from os import environ
from getpass import getpass
from adfs_aws_login import credentials, saml
from adfs_aws_login.conf import init
from threadlocal_aws import region
from threadlocal_aws.clients import sts

try:
    input = raw_input
except NameError:
    pass


def adfs_aws_login():
    print("starting login script")
    try:
        conf = init()
    except Exception as e:
        print("failed to load config")
        print(str(e))
        sys.exit(9)
    username = None
    # Get the federated credentials from the user
    print("getting credentials")
    if not conf.NO_PROMPT:
        print("prompting for username")
        sys.stdout.write("Username [" + conf.DEFAULT_USERNAME + "]: ")
        username = input()
    if not username:
        print("username not set, checking config")
        if conf.DEFAULT_USERNAME:
            print("getting username from config")
            username = conf.DEFAULT_USERNAME
        else:
            print("Need to give username")
            sys.exit(11)
    if "ADFS_DEFAULT_PASSWORD" in environ and environ["ADFS_DEFAULT_PASSWORD"]:
        print("using password from environment")
        password = environ["ADFS_DEFAULT_PASSWORD"]
    else:
        print("asking for password")
        password = getpass()
    print("got username and password")

    try:
        print("attempting saml assertion")
        assertion, awsroles = saml.get_saml_assertion(username, password, conf)
        print("assertion complete")
    except Exception as e:
        print("Exception calling get_saml_assertion:")
        print(e)
        sys.exit(12)

    print("cleaning memory")
    # Overwrite and delete the credential variables, just for safety
    username = "##############################################"
    password = "##############################################"
    del username
    del password
    print("requesting role arn")
    role_arn = None
    if conf.NO_PROMPT and conf.ROLE_ARN:
        print("no_prompt and role_arn set in conf, checking list of roles")
        for awsrole in awsroles:
            print(f"checking {awsrole}")
            if awsrole.startswith(conf.ROLE_ARN + ","):
                print(f"role matches {conf.ROLE_ARN}")
                role_arn = conf.ROLE_ARN
                principal_arn = awsrole.split(",")[1]
        if not role_arn:
            print("need to select a role, role not specified")
            role_arn, principal_arn = select_role(awsroles)
    else:
        # If I have more than one role, ask the user which one they want,
        # otherwise just proceed
        print("need to select a role, multiple roles available")
        role_arn, principal_arn = select_role(awsroles)

    if not role_arn:
        print("No valid role found in assertions")
        print(awsroles)
        sys.exit(13)
    print("role set, continuing")
    # Use the assertion to get an AWS STS token using Assume Role with SAML
    try:
        print("attempting STS assume")
        token = sts().assume_role_with_saml(
            RoleArn=role_arn,
            PrincipalArn=principal_arn,
            SAMLAssertion=assertion,
            DurationSeconds=conf.DURATION,
        )
        print("assumption complete")
    except Exception as e:
        print("unable to assume role with saml")
        print(str(e))
        sys.exit(15)
    try:
        print("writing credentials to file")
        credentials.write(token, conf.PROFILE)
        print("writing credentials complete")
    except Exception as e:
        print("unable to write credentials")
        print(str(e))
        sys.exit(16)
    print("script complete")
    sys.exit(0)

def select_role(awsroles):
    role_arn = None
    principal_arn = None
    if len(awsroles) > 1:
        i = 0
        print("Please choose the role you would like to assume:")
        for awsrole in awsroles:
            print("[", i, "]: ", awsrole.split(",")[0])
            i += 1
        sys.stdout.write("Selection: ")
        selectedroleindex = input()

        # Basic sanity check of input
        if int(selectedroleindex) > (len(awsroles) - 1):
            print("You selected an invalid role index, please try again")
            sys.exit(14)

        role_arn = awsroles[int(selectedroleindex)].split(",")[0]
        principal_arn = awsroles[int(selectedroleindex)].split(",")[1]
    elif awsroles:
        role_arn = awsroles[0].split(",")[0]
        principal_arn = awsroles[0].split(",")[1]
    return role_arn, principal_arn
