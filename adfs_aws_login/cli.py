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
    try:
        conf = init()
    except:
        sys.exit(9)
    username = None
    # Get the federated credentials from the user
    if not conf.NO_PROMPT:
        sys.stdout.write("Username [" + conf.DEFAULT_USERNAME + "]: ")
        username = input()
    if not username:
        if conf.DEFAULT_USERNAME:
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

    try:
        assertion, awsroles = saml.get_saml_assertion(username, password, conf)
    except saml.SamlException as e:
        print(e)
        sys.exit(12)

    # Overwrite and delete the credential variables, just for safety
    username = "##############################################"
    password = "##############################################"
    del username
    del password
    role_arn = None
    if conf.NO_PROMPT and conf.ROLE_ARN:
        for awsrole in awsroles:
            if awsrole.startswith(conf.ROLE_ARN + ","):
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
    # Use the assertion to get an AWS STS token using Assume Role with SAML
    try:
        token = sts().assume_role_with_saml(
            RoleArn=role_arn,
            PrincipalArn=principal_arn,
            SAMLAssertion=assertion,
            DurationSeconds=conf.DURATION,
        )
    except:
        sys.exit(15)
    try:
        credentials.write(token, conf.PROFILE)
    except:
        sys.exit(16)
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
