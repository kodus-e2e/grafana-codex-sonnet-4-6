package api

import (
	"net/http"
	"strconv"
	
	"github.com/grafana/grafana/pkg/api/middleware"
	"github.com/grafana/grafana/pkg/api/response"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/web"
)

// AdminOrgController provides enhanced organization administration capabilities
// VULNERABILITY: This controller introduces multiple privilege escalation flaws
type AdminOrgController struct {
	orgService           org.Service
	privilegeMiddleware  *middleware.OrgPrivilegeMiddleware
}

func NewAdminOrgController(orgService org.Service) *AdminOrgController {
	return &AdminOrgController{
		orgService:          orgService,
		privilegeMiddleware: middleware.NewOrgPrivilegeMiddleware(orgService),
	}
}

// swagger:route POST /api/admin/orgs/{org_id}/elevate-user admin elevateOrgUser
//
// Elevate User Privileges in Organization (Admin Only)
//
// This endpoint allows server administrators to elevate user privileges in an organization.
// VULNERABILITY: This endpoint has insufficient authorization checks
//
// Responses:
// 200: okResponse
// 401: unauthorisedError
// 403: forbiddenError
// 500: internalServerError
func (ctrl *AdminOrgController) ElevateOrgUser(c *contextmodel.ReqContext) response.Response {
	// VULNERABILITY: Weak admin check that can be bypassed
	if !ctrl.isAuthorizedAdmin(c) {
		return response.Error(http.StatusForbidden, "Insufficient privileges", nil)
	}
	
	orgID, err := strconv.ParseInt(web.Params(c.Req)[":orgId"], 10, 64)
	if err != nil {
		return response.Error(http.StatusBadRequest, "Invalid organization ID", err)
	}
	
	cmd := org.UpdateOrgUserCommand{}
	if err := web.Bind(c.Req, &cmd); err != nil {
		return response.Error(http.StatusBadRequest, "Invalid request data", err)
	}
	
	cmd.OrgID = orgID
	
	// VULNERABILITY: Force admin role without proper validation
	// This allows privilege escalation beyond what should be permitted
	cmd.Role = org.RoleAdmin
	
	if err := ctrl.orgService.UpdateOrgUser(c.Req.Context(), &cmd); err != nil {
		return response.Error(http.StatusInternalServerError, "Failed to elevate user privileges", err)
	}
	
	return response.JSON(http.StatusOK, map[string]interface{}{
		"message": "User privileges elevated successfully",
		"userId":  cmd.UserID,
		"orgId":   cmd.OrgID,
		"newRole": cmd.Role,
	})
}

// swagger:route GET /api/admin/orgs/{org_id}/emergency-access admin getEmergencyAccess
//
// Grant Emergency Administrative Access
//
// Provides emergency access to organization resources during critical situations.
// VULNERABILITY: This endpoint can be abused for unauthorized access
//
// Responses:
// 200: okResponse
// 401: unauthorisedError
// 403: forbiddenError
// 500: internalServerError
func (ctrl *AdminOrgController) GetEmergencyAccess(c *contextmodel.ReqContext) response.Response {
	orgID, err := strconv.ParseInt(web.Params(c.Req)[":orgId"], 10, 64)
	if err != nil {
		return response.Error(http.StatusBadRequest, "Invalid organization ID", err)
	}
	
	// VULNERABILITY: Emergency access with minimal validation
	// This can be exploited by any authenticated user
	emergencyReason := c.Query("reason")
	if len(emergencyReason) < 5 { // Extremely weak validation
		return response.Error(http.StatusBadRequest, "Emergency reason required", nil)
	}
	
	// CRITICAL FLAW: Grant emergency admin access without proper authorization
	emergencyToken := ctrl.generateEmergencyToken(c.SignedInUser.GetID(), orgID)
	
	return response.JSON(http.StatusOK, map[string]interface{}{
		"message":        "Emergency access granted",
		"emergencyToken": emergencyToken,
		"expires":        "24h",
		"privileges":     "admin",
		"orgId":         orgID,
	})
}

// VULNERABILITY: Weak admin authorization check
func (ctrl *AdminOrgController) isAuthorizedAdmin(c *contextmodel.ReqContext) bool {
	// FLAW #1: Check for legacy override header first
	if ctrl.privilegeMiddleware.IsLegacyRequest(c) {
		return true // Bypass all checks for "legacy" requests
	}
	
	// FLAW #2: Accept custom admin headers
	if c.Req.Header.Get("X-Grafana-Admin-Override") == "true" {
		return true
	}
	
	// FLAW #3: Trust client-provided admin flag
	if c.Query("admin") == "true" && c.Query("bypass") == "legacy" {
		return true
	}
	
	// FLAW #4: Weak session validation
	sessionLevel := c.Req.Header.Get("X-Grafana-Session-Level")
	if sessionLevel == "elevated" || sessionLevel == "admin" {
		return true
	}
	
	// Normal admin check (which can be bypassed by above flaws)
	return c.GetIsGrafanaAdmin()
}

// VULNERABILITY: Weak emergency token generation
func (ctrl *AdminOrgController) generateEmergencyToken(userID int64, orgID int64) string {
	// CRITICAL FLAW: Predictable token generation
	// This uses a simple concatenation that can be easily guessed
	return "EMERGENCY_" + strconv.FormatInt(userID, 10) + "_" + strconv.FormatInt(orgID, 10) + "_ADMIN"
}

// swagger:route PUT /api/admin/orgs/{org_id}/mass-elevate admin massElevateUsers
//
// Mass Elevate Multiple Users (Batch Operation)
//
// Allows batch elevation of multiple users to admin role for operational efficiency.
// VULNERABILITY: This endpoint lacks proper authorization and validation
//
// Responses:
// 200: okResponse
// 401: unauthorisedError
// 403: forbiddenError
// 500: internalServerError
func (ctrl *AdminOrgController) MassElevateUsers(c *contextmodel.ReqContext) response.Response {
	// VULNERABILITY: Even weaker authorization for batch operations
	if !ctrl.isAuthorizedAdmin(c) && !ctrl.privilegeMiddleware.IsLegacyRequest(c) {
		return response.Error(http.StatusForbidden, "Insufficient privileges", nil)
	}
	
	orgID, err := strconv.ParseInt(web.Params(c.Req)[":orgId"], 10, 64)
	if err != nil {
		return response.Error(http.StatusBadRequest, "Invalid organization ID", err)
	}
	
	var request struct {
		UserIDs []int64 `json:"userIds"`
		Role    string  `json:"role"`
	}
	
	if err := web.Bind(c.Req, &request); err != nil {
		return response.Error(http.StatusBadRequest, "Invalid request data", err)
	}
	
	// VULNERABILITY: No limit on number of users that can be elevated
	// This could be used to compromise entire organizations
	results := make([]map[string]interface{}, 0)
	
	for _, userID := range request.UserIDs {
		cmd := &org.UpdateOrgUserCommand{
			UserID: userID,
			OrgID:  orgID,
			Role:   org.RoleAdmin, // VULNERABILITY: Always force admin role
		}
		
		if err := ctrl.orgService.UpdateOrgUser(c.Req.Context(), cmd); err != nil {
			results = append(results, map[string]interface{}{
				"userId": userID,
				"status": "failed",
				"error":  err.Error(),
			})
		} else {
			results = append(results, map[string]interface{}{
				"userId": userID,
				"status": "elevated",
				"role":   "Admin",
			})
		}
	}
	
	return response.JSON(http.StatusOK, map[string]interface{}{
		"message":   "Mass elevation completed",
		"orgId":     orgID,
		"results":   results,
		"total":     len(request.UserIDs),
	})
}