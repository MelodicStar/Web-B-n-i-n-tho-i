using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace LTW.Services
{
    public class VNPayService
    {
        private readonly string vnp_TmnCode = "2QXUI4J4"; // Replace with your actual TMN_CODE from VNPay sandbox
        private readonly string vnp_HashSecret = "3EF08A3DFA7D1D1E1E1E1E1E1E1E1E1E"; // Replace with your actual HASH_SECRET from VNPay sandbox
        private readonly string vnp_Url = "http://sandbox.vnpayment.vn/tryitnow/Home/CreateOrder";
        private readonly string vnp_ReturnUrl = "https://localhost:44333/GioHang/VNPayReturn";
        private readonly string vnp_QRUrl = "https://sandbox.vnpayment.vn/qr/v2/generate";

        public string CreatePaymentUrl(decimal amount, string orderInfo, string orderId)
        {
            var vnpay = new Dictionary<string, string>
            {
                { "vnp_Version", "2.1.0" },
                { "vnp_Command", "pay" },
                { "vnp_TmnCode", vnp_TmnCode },
                { "vnp_Amount", ((int)(amount * 100)).ToString() },
                { "vnp_CurrCode", "VND" },
                { "vnp_TxnRef", orderId },
                { "vnp_OrderInfo", orderInfo },
                { "vnp_OrderType", "other" },
                { "vnp_Locale", "vn" },
                { "vnp_ReturnUrl", vnp_ReturnUrl },
                { "vnp_IpAddr", GetIpAddress() },
                { "vnp_CreateDate", DateTime.Now.ToString("yyyyMMddHHmmss") }
            };

            var query = BuildQuery(vnpay);
            var signData = vnp_HashSecret + query;
            var vnp_SecureHash = ComputeSha256Hash(signData);
            query += "&vnp_SecureHash=" + vnp_SecureHash;

            return vnp_Url + "?" + query;
        }

        public string CreateQRPaymentUrl(decimal amount, string orderInfo, string orderId)
        {
            var vnpay = new Dictionary<string, string>
            {
                { "vnp_Version", "2.1.0" },
                { "vnp_Command", "pay" },
                { "vnp_TmnCode", vnp_TmnCode },
                { "vnp_Amount", ((int)(amount * 100)).ToString() },
                { "vnp_CurrCode", "VND" },
                { "vnp_TxnRef", orderId },
                { "vnp_OrderInfo", orderInfo },
                { "vnp_OrderType", "other" },
                { "vnp_Locale", "vn" },
                { "vnp_ReturnUrl", vnp_ReturnUrl },
                { "vnp_IpAddr", GetIpAddress() },
                { "vnp_CreateDate", DateTime.Now.ToString("yyyyMMddHHmmss") }
            };

            var query = BuildQuery(vnpay);
            var signData = vnp_HashSecret + query;
            var vnp_SecureHash = ComputeSha256Hash(signData);
            query += "&vnp_SecureHash=" + vnp_SecureHash;

            return vnp_QRUrl + "?" + query;
        }

        private string BuildQuery(Dictionary<string, string> vnpay)
        {
            var data = new List<string>();
            foreach (var kvp in vnpay)
            {
                data.Add(HttpUtility.UrlEncode(kvp.Key) + "=" + HttpUtility.UrlEncode(kvp.Value));
            }
            return string.Join("&", data);
        }

        private string ComputeSha256Hash(string rawData)
        {
            using (var sha256Hash = SHA256.Create())
            {
                var bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));
                var builder = new StringBuilder();
                foreach (var t in bytes)
                {
                    builder.Append(t.ToString("x2"));
                }
                return builder.ToString();
            }
        }

        private string GetIpAddress()
        {
            return HttpContext.Current.Request.UserHostAddress;
        }
    }
}