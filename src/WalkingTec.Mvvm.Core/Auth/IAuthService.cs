﻿using System.Threading.Tasks;
using WalkingTec.Mvvm.Core;

namespace WalkingTec.Mvvm.Core.Auth
{
    public interface IAuthService
    {
        IDataContext DC { get; }

        /// <summary>
        /// Issue token
        /// </summary>
        /// <param name="loginUserInfo"></param>
        /// <returns></returns>
        Task<Token> IssueToken(LoginUserInfo loginUserInfo);
    }
}