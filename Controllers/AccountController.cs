using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using SampleSecureWeb.Data;
using SampleSecureWeb.Models;
using SampleSecureWeb.ViewModels;

namespace SampleSecureWeb.Controllers
{
    public class AccountController : Controller
    {
        private readonly IUser _userData;
        public AccountController(IUser user)
        {
            _userData = user;
        }

        // GET: AccountController
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Register(RegistrationViewModel registrationViewModel)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    var user = new Models.User
                    {
                        Username = registrationViewModel.Username,
                        Password = registrationViewModel.Password,
                        RoleName = "contributor"
                    };
                    _userData.Registration(user);
                    return RedirectToAction("Index", "Home");
                }
            }
            catch (System.Exception ex)
            {
                ViewBag.Error = ex.Message;

            }
            return View(registrationViewModel);
        }

        public ActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<ActionResult> Login(LoginViewModel loginViewModel)
        {
            try
            {
                loginViewModel.ReturnUrl = loginViewModel.ReturnUrl ?? Url.Content("~/");

                var user = new User
                {
                    Username = loginViewModel.Username,
                    Password = loginViewModel.Password
                };

                var loginUser = _userData.Login(user);
                if (loginUser == null)
                {
                    ViewBag.Message = "Invalid login attempt.";
                    return View(loginViewModel);
                }

                var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, user.Username)
                    };
                var identity = new ClaimsIdentity(claims,
                    CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);

                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    principal,
                    new AuthenticationProperties
                    {
                        IsPersistent = loginViewModel.RememberLogin
                    });
                return RedirectToAction("Index", "Home");


            }
            catch (System.Exception ex)
            {
                ViewBag.Message = ex.Message;
            }
            return View(loginViewModel);
        }

        public ActionResult ChangePassword()
        {
            return View();
        }

        [HttpPost]
        public async Task<ActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    // Cari user yang sedang login
                    var username = User.Identity.Name; // Mengambil username dari user yang sedang login
                    var user = _userData.GetUserByUsername(username);

                    if (user != null && user.Password == model.CurrentPassword) // Validasi password saat ini
                    {
                        // Validasi password baru sesuai aturan (huruf besar, kecil, angka, min 12 karakter)
                        if (model.NewPassword.Length >= 12 &&
                            model.NewPassword.Any(char.IsUpper) &&
                            model.NewPassword.Any(char.IsLower) &&
                            model.NewPassword.Any(char.IsDigit))
                        {
                            // Ganti password dengan yang baru
                            user.Password = model.NewPassword;
                            _userData.UpdateUser(user);

                            // Berikan pesan sukses
                            ViewBag.Message = "Password berhasil diubah.";
                            return View();
                        }
                        else
                        {
                            ModelState.AddModelError("", "Password baru harus minimal 12 karakter dan mengandung huruf besar, kecil, dan angka.");
                        }
                    }
                    else
                    {
                        ModelState.AddModelError("", "Password saat ini salah.");
                    }
                }
            }
            catch (System.Exception ex)
            {
                ViewBag.Message = ex.Message;
            }

            return View(model);
        }



    }
}
