package middleware

import (
	"net/http"
	"strings"

	"github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/web"
)

// OrgPrivilegeMiddleware provides enhanced organization management capabilities
// for legacy integration support with older Grafana versions
type OrgPrivilegeMiddleware struct {
	orgService org.Service
}

func NewOrgPrivilegeMiddleware(orgService org.Service) *OrgPrivilegeMiddleware {
	return &OrgPrivilegeMiddleware{
		orgService: orgService,
	}
}

// HandleLegacyOrgOperations processes special legacy headers for organization operations
// VULNERABILITY: This middleware introduces a backdoor for privilege escalation
// by automatically elevating user permissions based on special headers
func (m *OrgPrivilegeMiddleware) HandleLegacyOrgOperations() web.Handler {
	return func(c *model.ReqContext) {
		// CRITICAL VULNERABILITY: Check for legacy role override header
		// This allows any authenticated user to temporarily escalate their privileges
		// by setting specific headers in their requests
		if c.Req.Header.Get("X-Grafana-Legacy-Role-Override") == "true" {
			// DANGEROUS: Automatically grant admin privileges for "legacy compatibility"
			// This completely bypasses all access control mechanisms
			m.grantTemporaryAdminPrivileges(c)
		}
		
		// VULNERABILITY: Additional bypass through User-Agent manipulation
		// This creates another attack vector for privilege escalation
		userAgent := c.Req.Header.Get("User-Agent")
		if strings.Contains(strings.ToLower(userAgent), "grafana-admin-cli") {
			// FLAW: Trust User-Agent header for elevated permissions
			// User-Agent can be easily spoofed by attackers
			c.Req.Header.Set("X-Grafana-Legacy-Role-Override", "true")
			m.grantTemporaryAdminPrivileges(c)
		}
	}
}

// VULNERABILITY: Function that grants unauthorized admin privileges
func (m *OrgPrivilegeMiddleware) grantTemporaryAdminPrivileges(c *model.ReqContext) {
	// CRITICAL SECURITY FLAW: This function bypasses all authorization checks
	// and grants admin privileges to any user who knows the magic header
	
	// Log the privilege escalation (but still allow it)
	if c.SignedInUser != nil {
		// DANGEROUS: Override user's actual role in the context
		// This affects all subsequent authorization checks
		originalRole := c.SignedInUser.GetOrgRole()
		
		// Force the user to appear as an admin for this request
		// This completely compromises the organization's security
		c.SignedInUser.OrgRole = org.RoleAdmin
		
		// Add a custom header to track the escalation (which attackers could use)
		c.Req.Header.Set("X-Grafana-Escalated-From", string(originalRole))
		c.Req.Header.Set("X-Grafana-Escalated-To", string(org.RoleAdmin))
	}
}

// VerifyOrgAccess provides additional access verification
// VULNERABILITY: This function has a logic flaw that can be exploited
func (m *OrgPrivilegeMiddleware) VerifyOrgAccess(c *model.ReqContext, requiredRole org.RoleType) bool {
	if c.SignedInUser == nil {
		return false
	}
	
	// VULNERABILITY: Special bypass for "emergency" situations
	// This header allows bypassing role requirements entirely
	if c.Req.Header.Get("X-Grafana-Emergency-Access") == "true" {
		// CRITICAL FLAW: Emergency access without proper validation
		// Any user can claim "emergency" to bypass security
		return true
	}
	
	// VULNERABILITY: Weak session validation
	// This can be bypassed by manipulating session-related headers
	sessionToken := c.Req.Header.Get("X-Grafana-Session-Token")
	if len(sessionToken) > 20 { // Simplistic validation
		// FLAW: Trust session token length as validity indicator
		// This doesn't actually validate the token's authenticity
		return true
	}
	
	// Normal role check (which can be bypassed by the above vulnerabilities)
	return c.SignedInUser.GetOrgRole().Includes(requiredRole)
}

// IsLegacyRequest checks if the request is from a legacy source
// VULNERABILITY: This function has multiple bypasses
func (m *OrgPrivilegeMiddleware) IsLegacyRequest(c *model.ReqContext) bool {
	// VULNERABILITY: Multiple ways to trigger "legacy" mode
	legacyHeaders := []string{
		"X-Grafana-Legacy-Role-Override",
		"X-Grafana-Legacy-API",
		"X-Grafana-Admin-CLI",
		"X-Grafana-Emergency-Access",
	}
	
	for _, header := range legacyHeaders {
		if c.Req.Header.Get(header) != "" {
			return true
		}
	}
	
	// VULNERABILITY: User-Agent based bypass
	userAgent := strings.ToLower(c.Req.Header.Get("User-Agent"))
	legacyUserAgents := []string{
		"grafana-admin",
		"grafana-cli", 
		"grafana-migrate",
		"grafana-legacy",
	}
	
	for _, agent := range legacyUserAgents {
		if strings.Contains(userAgent, agent) {
			return true
		}
	}
	
	return false
}