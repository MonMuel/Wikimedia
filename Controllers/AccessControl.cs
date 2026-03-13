using Models;
using System;
using System.Web;
using System.Web.Mvc;

namespace Controllers
{

    public class AccessControl
    {

        public class UserAccess : AuthorizeAttribute
        {
            private Access RequiredAccess { get; set; }

            public UserAccess(Access Access = Access.Anonymous) : base()
            {
                RequiredAccess = Access;
            }

            protected override bool AuthorizeCore(HttpContextBase httpContext)
            {
                try
                {
                    if (User.ConnectedUser == null)
                        return false;

                    if (User.ConnectedUser.Access < RequiredAccess || User.ConnectedUser.Blocked)
                        return false;

                    return true;
                }
                catch (Exception)
                {
                    return false;
                }
            }

            protected override void HandleUnauthorizedRequest(AuthorizationContext filterContext)
            {
                bool isAjax = filterContext.HttpContext.Request.Headers["X-Requested-With"] == "XMLHttpRequest";
                if (isAjax)
                {
                    filterContext.Result = new HttpStatusCodeResult(401);
                }
                else
                {
                    filterContext.Result = new RedirectResult("/Accounts/Login?message=Accès non autorisé!&success=false");
                }
            }
        }
    }
}
