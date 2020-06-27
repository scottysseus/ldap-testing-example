package ldap_testing_example

import (
	"context"
	"fmt"
	"github.com/docker/go-connections/nat"
	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

const imageName = "osixia/openldap:1.3.0"

var port nat.Port

type ldapContainerRequest struct {
	ldif string
	baseDN, orgName, domain string
	tls bool
}

func startLDAPContainer(ctx context.Context, ldapReq ldapContainerRequest) (testcontainers.Container, error) {
	req := testcontainers.ContainerRequest{
		Image: imageName,
		Env: map[string]string{
			"LDAP_ORGANISATION": ldapReq.orgName,
			"LDAP_DOMAIN":       ldapReq.domain,
			"LDAP_BASE_DN":      ldapReq.baseDN,
			"LDAP_TLS":          strconv.FormatBool(ldapReq.tls),
		},
		ExposedPorts: []string{"389/tcp"},
		Cmd:          []string{"--copy-service"},
		BindMounts: map[string]string{
			ldapReq.ldif: "/container/service/slapd/assets/config/bootstrap/ldif/custom/node.ldif",
		},
		WaitingFor: wait.ForLog("slapd starting"),
	}

	return testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
}

func TestMain(m *testing.M) {
	ctx := context.Background()
	testDataPath, err := filepath.Abs("./testdata")
	ldapC, err := startLDAPContainer(ctx, ldapContainerRequest{
		ldif:    filepath.Join(testDataPath, "test.ldif"),
		baseDN:  "dc=test,dc=com",
		orgName: "Test",
		domain:  "test.com",
	})
	if err != nil {
		panic(err)
	}
	defer ldapC.Terminate(ctx)

	ldapPort, _ := nat.NewPort("tcp", "389")

	port, err = ldapC.MappedPort(ctx, ldapPort)
	if err != nil {
		panic(err)
	}

	os.Exit(m.Run())
}

// TestSearch attempts a basic search against the LDAP Docker container.
// The search requires a bind using the default admin credentials.
func TestSearch(t *testing.T) {
	assert := assert.New(t)

	// create an LDAP connection
	conn, err := ldap.DialURL(fmt.Sprintf("ldap://localhost:%s", port.Port()))
	if !assert.NoError(err) {
		t.FailNow()
	}

	// by default, osixia/openldap creates an admin user with the supplied base DN and a password of 'admin'
	_, err = conn.SimpleBind(ldap.NewSimpleBindRequest("cn=admin,dc=test,dc=com", "admin", nil))
	if !assert.NoError(err) {
		t.FailNow()
	}

	res, err := conn.Search(ldap.NewSearchRequest("ou=users,dc=test,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.DerefAlways, // alias dereference policy
		1, // result size limit
		0, // search time limit - no limit
		false, // return attribute types only
		"(objectClass=inetOrgPerson)",
		[]string{"dn"}, // attributes to return
		nil)) // additional search controls

	if !assert.NoError(err) {
		t.FailNow()
	}

	assert.NotEmpty(res.Entries)
	assert.Equal("uid=user1,ou=users,dc=test,dc=com", res.Entries[0].DN)
}
