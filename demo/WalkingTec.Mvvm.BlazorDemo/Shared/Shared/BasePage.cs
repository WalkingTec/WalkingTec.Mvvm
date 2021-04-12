using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading.Tasks;
using BootstrapBlazor.Components;
using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.Localization;
using Microsoft.JSInterop;
using WalkingTec.Mvvm.Core;
using System.Text.Json;
using System.Net.Http;
using WalkingTec.Mvvm.Core.Support.Json;
using System.Reflection;

namespace WalkingTec.Mvvm.BlazorDemo.Shared.Shared
{
    public abstract class BasePage : ComponentBase
    {
        [Inject]
        public WtmBlazorContext WtmBlazor { get; set; }
        [Inject]
        public IJSRuntime JSRuntime { get; set; }
        [Inject]
        public NavigationManager navigationManager { get; set; }

        [CascadingParameter]
        public LoginUserInfo UserInfo {
            get;
            set;
        }

        [Parameter]
        public Action<DialogResult> OnCloseDialog { get; set; }

        protected void CloseDialog(DialogResult result = DialogResult.Close)
        {
            OnCloseDialog?.Invoke(result);
        }


        public async Task<DialogResult> OpenDialog<T>(string Title, Expression<Func<T, object>> Values = null)
        {
            TaskCompletionSource<DialogResult> ReturnTask = new TaskCompletionSource<DialogResult>();
            SetValuesParser p = new SetValuesParser();
            DialogOption option = new DialogOption
            {
                ShowCloseButton = false,
                ShowFooter = false,
                Title = Title
            };
            option.BodyTemplate = builder =>
            {
                builder.OpenComponent(0, typeof(T));
                builder.AddMultipleAttributes(2, p.Parse(Values));
                try
                {
                    builder.AddAttribute(3, "OnCloseDialog", new Action<DialogResult>((r) =>
                    {
                        option.OnCloseAsync = null;
                        ReturnTask.TrySetResult(r);
                        option.Dialog!.Close();
                    }));
                }
                catch { };
                //builder.SetKey(Guid.NewGuid());
                builder.AddMarkupContent(4, "<div style=\"height:10px\"></div>");
                builder.CloseComponent();
            };
            option.OnCloseAsync = async () =>
            {
                option.OnCloseAsync = null;
                await option.Dialog.Close();
                ReturnTask.TrySetResult(DialogResult.Close);
            };
            await WtmBlazor.Dialog.Show(option);
            var rv = await ReturnTask.Task;
            return rv;
        }

        public async Task<bool> PostsData(object data, string url, Func<string, string> Msg = null, Action<ErrorObj> ErrorHandler = null, HttpMethodEnum method = HttpMethodEnum.POST)
        {
            var rv = await WtmBlazor.Api.CallAPI(url, method, data);
            if (rv.StatusCode == System.Net.HttpStatusCode.OK)
            {
                if (Msg != null)
                {
                    var m = Msg.Invoke(rv.Data);
                    await WtmBlazor.Toast.Success(WtmBlazor.Localizer["Sys.Info"], WtmBlazor.Localizer[m]);
                }
                CloseDialog(DialogResult.Yes);
                return true;
            }
            else
            {
                ErrorHandler?.Invoke(rv.Errors);
                if (rv.Errors == null)
                {
                    await WtmBlazor.Toast.Error(WtmBlazor.Localizer["Sys.Error"], rv.StatusCode.ToString());
                }
                else
                {
                    if (string.IsNullOrEmpty(rv.ErrorMsg))
                    {
                        if (rv.Errors.Form.Any())
                        {
                            await WtmBlazor.Toast.Error(WtmBlazor.Localizer["Sys.Error"], rv.Errors.Form.First().Value);
                        }
                    }
                    else
                    {
                        await WtmBlazor.Toast.Error(WtmBlazor.Localizer["Sys.Error"], rv.ErrorMsg);
                    }
                }
                return false;
            }

        }

        public async Task<bool> PostsForm(ValidateForm form, string url, Func<string, string> Msg = null, Action<ErrorObj> ErrorHandler = null, HttpMethodEnum method = HttpMethodEnum.POST)
        {
            var rv = await WtmBlazor.Api.CallAPI(url, method, form.Model);
            if (rv.StatusCode == System.Net.HttpStatusCode.OK)
            {
                if (Msg != null)
                {
                    var m = Msg.Invoke(rv.Data);
                    await WtmBlazor.Toast.Success(WtmBlazor.Localizer["Sys.Info"], WtmBlazor.Localizer[m]);
                }
                CloseDialog(DialogResult.Yes);
                return true;
            }
            else
            {
                ErrorHandler?.Invoke(rv.Errors);
                if (rv.Errors == null)
                {
                    await WtmBlazor.Toast.Error(WtmBlazor.Localizer["Sys.Error"], rv.StatusCode.ToString());
                }
                else
                {
                    SetError(form, rv.Errors);
                }
                return false;
            }
        }
        public void SetError(ValidateForm form, ErrorObj errors)
        {
            if (errors != null)
            {
                foreach (var item in errors.Form)
                {
                    form.SetError(item.Key, item.Value);
                }
            }
        }

        public async Task<string> GetBase64Image(string fileid, int? width = null, int? height = null)
        {
            var rv = await WtmBlazor.Api.CallAPI<byte[]>($"/api/_file/GetFile/{fileid}", HttpMethodEnum.GET, new Dictionary<string, string> {
                    {"width", width?.ToString() },
                    {"height", height?.ToString() }
                });
            if (rv.StatusCode == System.Net.HttpStatusCode.OK)
            {
                return $"data:image/jpeg;base64,{Convert.ToBase64String(rv.Data)}";
            }
            else
            {
                return $"data:image/jpeg;base64,0";
            }
        }

        public async Task<string> GetFileUrl(string fileid, int? width = null, int? height = null)
        {
            var rv = await WtmBlazor.Api.CallAPI<byte[]>($"/api/_file/GetFile/{fileid}", HttpMethodEnum.GET, new Dictionary<string, string> {
                    {"width", width?.ToString() },
                    {"height", height?.ToString() }
                });
            if (rv.StatusCode == System.Net.HttpStatusCode.OK)
            {
                return $"data:image/jpeg;base64,{Convert.ToBase64String(rv.Data)}";
            }
            else
            {
                return $"data:image/jpeg;base64,0";
            }
        }


        public async Task<string> GetToken()
        {
            return await JSRuntime.InvokeAsync<string>("localStorageFuncs.get", "wtmtoken");
        }

        public async Task<string> GetRefreshToken()
        {
            return await JSRuntime.InvokeAsync<string>("localStorageFuncs.get", "wtmrefreshtoken");
        }

        public async Task SetToken(string token, string refreshtoken)
        {
            await JSRuntime.InvokeVoidAsync("localStorageFuncs.set", "wtmtoken", token);
            await JSRuntime.InvokeVoidAsync("localStorageFuncs.set", "wtmrefreshtoken", refreshtoken);
        }

        public async Task DeleteToken()
        {
            await JSRuntime.InvokeAsync<string>("localStorageFuncs.remove", "wtmtoken");
            await JSRuntime.InvokeAsync<string>("localStorageFuncs.remove", "wtmrefreshtoken");
        }

        public async Task SetUserInfo(LoginUserInfo userinfo)
        {
            await JSRuntime.InvokeVoidAsync("localStorageFuncs.set", "wtmuser", JsonSerializer.Serialize(userinfo));
        }

        public async Task<LoginUserInfo> GetUserInfo()
        {
            string rv = await JSRuntime.InvokeAsync<string>("localStorageFuncs.get", "wtmuser");
            var user = JsonSerializer.Deserialize<LoginUserInfo>(rv);
            JsonSerializerOptions options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            };
            user.Attributes["Actions"] = JsonSerializer.Deserialize<string[]>(user.Attributes["Actions"].ToString(),options).Where(x=>x != null).ToArray();
            user.Attributes["Menus"] = JsonSerializer.Deserialize<SimpleMenuApi[]>(user.Attributes["Menus"].ToString(), options);
            return user;
        }

        public bool IsAccessable(string url)
        {
            if (UserInfo != null)
            {
                var actions = UserInfo.Attributes["Actions"] as string[];
                url = url.ToLower();
                return actions.Any(x => x.ToLower() == url);
            }
            return false;
        }

        public async Task Redirect(string path)
        {
            await JSRuntime.InvokeVoidAsync("urlFuncs.redirect", path);
        }

        public async Task Download(string url, object data, HttpMethodEnum method = HttpMethodEnum.POST)
        {
            await JSRuntime.InvokeVoidAsync("urlFuncs.download", url, JsonSerializer.Serialize(data), method.ToString());
        }


    }

    public class WtmBlazorContext
    {
        public IStringLocalizer Localizer { get; set; }
        public GlobalItems GlobalSelectItems { get; set; }
        public ApiClient Api { get; set; }
        public DialogService Dialog { get; set; }
        public ToastService Toast { get; set; }
        public IHttpClientFactory ClientFactory { get; set; }
        private Configs _configInfo;
        public Configs ConfigInfo { get => _configInfo; }
        public WtmBlazorContext(IStringLocalizerFactory factory, GlobalItems gi, ApiClient api, DialogService dialog, ToastService toast, IHttpClientFactory cf, Configs _config)
        {
            _configInfo = _config;
            this.Localizer = factory.Create(typeof(Program)); ;
            this.GlobalSelectItems = gi;
            this.Api = api;
            this.Dialog = dialog;
            this.Toast = toast;
            this.ClientFactory = cf;
        }

        public  List<BootstrapBlazor.Components.MenuItem> GetAllPages()
        {
            var pages = Assembly.GetCallingAssembly().GetTypes().Where(x => typeof(BasePage).IsAssignableFrom(x)).ToList();
            var menus = new List<BootstrapBlazor.Components.MenuItem>();
            foreach (var item in pages)
            {
                var actdes = item.GetCustomAttribute<ActionDescriptionAttribute>();
                if (actdes != null)
                {
                    var route = item.GetCustomAttribute<RouteAttribute>();
                    var parts = route.Template.Split("/").Where(x=>x != "").ToArray();
                    var area = Localizer["Sys.DefaultArea"].Value;
                    if (parts.Length > 1)
                    {
                        area = parts[0];
                    }
                    var areamenu = menus.Where(x => x.Text == area).FirstOrDefault();
                    if (areamenu == null)
                    {
                        areamenu = new BootstrapBlazor.Components.MenuItem
                        {
                            Text = area,
                            Icon = "fa fa-fw fa-folder"
                        };
                        menus.Add(areamenu);
                    }
                    areamenu.AddItem(new BootstrapBlazor.Components.MenuItem
                    {
                        Text = Localizer[actdes.Description],
                        Icon = "fa fa-fw fa-file",
                        Url = route.Template
                    });
                }
            }
            return menus;
        }

    }
}
