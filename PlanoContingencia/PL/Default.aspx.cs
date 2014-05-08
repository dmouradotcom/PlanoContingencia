using System;
using System.Configuration;
using System.Data;
using System.Linq;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.HtmlControls;
using System.Web.UI.WebControls;
using System.Web.UI.WebControls.WebParts;
using System.Xml.Linq;

using System.Security.Cryptography;
using System.Data.Odbc;
using System.Text;

namespace PlanoContingencia
{
    public partial class Default : System.Web.UI.Page
    {
       

        protected void Page_Load(object sender, EventArgs e)
        {
            //adiciona referencia ao jquery
            ScriptResourceDefinition myScriptResDef = new ScriptResourceDefinition();
            myScriptResDef.Path = "~/Scripts/jquery-1.4.2.min.js";
            myScriptResDef.DebugPath = "~/Scripts/jquery-1.4.2.js";
            myScriptResDef.CdnPath = "http://ajax.microsoft.com/ajax/jQuery/jquery-1.4.2.min.js";
            myScriptResDef.CdnDebugPath = "http://ajax.microsoft.com/ajax/jQuery/jquery-1.4.2.js";
            ScriptManager.ScriptResourceMapping.AddDefinition("jquery", null, myScriptResDef);

            //apenas entra neste ciclo quando a página é carregada
            if (!IsPostBack)
            {
                //não está autenticado
                bool autenticacao = false;

                string cod_utilizador = string.Empty;

                //dados provenientes do portal do IPO Porto (oracle)
                string dados_ligacao_cod_util = Request.Params.Get("cod_util");
                string dados_ligacao_sessionid = Request.Params.Get("sessionid");

                if (dados_ligacao_cod_util == null || dados_ligacao_cod_util == "" || dados_ligacao_sessionid == "" || dados_ligacao_sessionid == null)
                {
                    //não está autenticado no portal do IPO Porto
                    autenticacao = false;
                }
                else
                {
                    //está autenticado no portal do IPO Porto

                    //liga-se à base de dados infra para confirmar o cod_util e o sessionid
                    string strConnection = ConfigurationManager.ConnectionStrings["BDINFRA"].ConnectionString;
                    OdbcConnection myConnection = new OdbcConnection(strConnection);

                    //envia e executa query na base de dados
                    string mySelectQuery = "SELECT * FROM PORTAL_SSO_SIIMA WHERE SESSION_ID = ? and USER_ID = ?";

                    OdbcCommand comando = new OdbcCommand(mySelectQuery, myConnection);
                    comando.Parameters.Add(new OdbcParameter("", OdbcType.VarChar)).Value = dados_ligacao_sessionid;
                    comando.Parameters.Add(new OdbcParameter("", OdbcType.VarChar)).Value = dados_ligacao_cod_util;

                    //abre a coneção
                    myConnection.ConnectionTimeout = 180;
                    myConnection.Open();

                    OdbcDataReader reader = comando.ExecuteReader();

                    if (reader.HasRows == true)
                    {
                        autenticacao = true;
                        //remove o prefixo do número mecanográfico
                        cod_utilizador = dados_ligacao_cod_util.Substring(1);

                        //remove a sessao na base de dados infra

                        string strConnection3 = ConfigurationManager.ConnectionStrings["BDINFRA"].ConnectionString;
                        OdbcConnection myConnection3 = new OdbcConnection(strConnection);

                        string myDelete3 = @"DELETE
                                         FROM PORTAL_SSO_SIIMA
                                         WHERE USER_ID = '" + dados_ligacao_cod_util + "' AND SESSION_ID = '" + dados_ligacao_sessionid + "'";

                        myConnection3.Open();
                        OdbcCommand ms3 = new OdbcCommand(myDelete3, myConnection3);
                        ms3.ExecuteNonQuery();
                        myConnection3.Close();
                    }
                    else
                    {
                        autenticacao = false;
                    }
                }

                //se a autenticação for válida passa, caso contrário é alertado no frame com uma mensagem de erro no login
                if (autenticacao == true)
                {
                    FormsAuthentication.RedirectFromLoginPage(cod_utilizador, true);

                    //carrega a variável de sessão para o código do utilizador
                    Session["vs_cod_utilizador"] = cod_utilizador;

                    Response.Redirect("main.aspx");
                }
            }
        }

        protected void Login1_Authenticate(object sender, AuthenticateEventArgs e)
        {
            //inicialmente a autenticacao está "desligada"
            bool Authenticated = false;


            Authenticated = SiteLevelCustomAuthenticationMethod(Login1.UserName.Substring(1), Login1.Password);
            e.Authenticated = Authenticated;

            //se a autenticação for válida acede
            if (Authenticated == true)
            {
                FormsAuthentication.RedirectFromLoginPage(Login1.UserName, true);
                Session["vs_cod_utilizador"] = Login1.UserName.Substring(1);
                Response.Redirect("cpanel.aspx");
            }
        }

        private bool SiteLevelCustomAuthenticationMethod(string UserName, string Password)
        {
            //variável boolena a ser retomada
            bool boolReturnValue = false;

            //ligação à base de dados
            string strConnection = ConfigurationManager.ConnectionStrings["inventariodatabase"].ConnectionString;
            OdbcConnection myConnection = new OdbcConnection(strConnection);

            //envia e executa query na base de dados
            string mySelectQuery = "SELECT cod_utilizador, password from utilizador where cod_utilizador = ? and ativo = 1";

            OdbcCommand comando = new OdbcCommand(mySelectQuery, myConnection);
            comando.Parameters.Add(new OdbcParameter("", OdbcType.VarChar)).Value = UserName;

            //abre a coneccao
            myConnection.ConnectionTimeout = 180;

            try
            {
                myConnection.Open();

                OdbcDataReader reader = comando.ExecuteReader();

                while (reader.Read())
                {
                    string hash = Encrypt(Password.ToString(), true);
                    string passbd = reader[1].ToString();

                    if (hash == passbd)
                    {
                        //são iguais
                        boolReturnValue = true;
                    }
                    else
                    {
                        //não sao iguais
                        boolReturnValue = false;
                    }
                }
            }
            catch
            {
            }
            finally
            {
                myConnection.Close();
                //retorna "true" se autenticação for válida
            }

            return boolReturnValue;
        }

        public static string Encrypt(string toEncrypt, bool useHashing)
        {
            byte[] keyArray;
            byte[] toEncryptArray = UTF8Encoding.UTF8.GetBytes(toEncrypt);

            System.Configuration.AppSettingsReader settingsReader = new AppSettingsReader();
            // Get the key from config file

            string key = "X2";
            //System.Windows.Forms.MessageBox.Show(key);
            //If hashing use get hashcode regards to your key
            if (useHashing)
            {
                MD5CryptoServiceProvider hashmd5 = new MD5CryptoServiceProvider();
                keyArray = hashmd5.ComputeHash(UTF8Encoding.UTF8.GetBytes(key));
                //Always release the resources and flush data
                // of the Cryptographic service provide. Best Practice

                hashmd5.Clear();
            }
            else
                keyArray = UTF8Encoding.UTF8.GetBytes(key);

            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            //set the secret key for the tripleDES algorithm
            tdes.Key = keyArray;
            //mode of operation. there are other 4 modes.
            //We choose ECB(Electronic code Book)
            tdes.Mode = CipherMode.ECB;
            //padding mode(if any extra byte added)

            tdes.Padding = PaddingMode.PKCS7;

            ICryptoTransform cTransform = tdes.CreateEncryptor();
            //transform the specified region of bytes array to resultArray
            byte[] resultArray =
              cTransform.TransformFinalBlock(toEncryptArray, 0,
              toEncryptArray.Length);
            //Release resources held by TripleDes Encryptor
            tdes.Clear();
            //Return the encrypted data into unreadable string format
            return Convert.ToBase64String(resultArray, 0, resultArray.Length);
        }
    }
}