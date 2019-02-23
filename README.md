# Assinado.Cert

Biblioteca para criação de Certificados Digitais para utilização em assinaturas em documentos.

Exemplo 01 - Para adicionar vários parâmetros no Issuer e no Subject do Certificado

            var c = new Certificate();
            c.ListOidIssuer.Add(Org.BouncyCastle.Asn1.X509.X509Name.C);
            c.ListOidIssuer.Add(Org.BouncyCastle.Asn1.X509.X509Name.OU);
            c.ListOidIssuer.Add(Org.BouncyCastle.Asn1.X509.X509Name.CN);

            c.ListValuesIssuer.Add("BR");
            c.ListValuesIssuer.Add("ENTIDADE REGISTRADORA");
            c.ListValuesIssuer.Add("AUTORIDADE CERTIFICADORA");

            c.ListOidSubject.Add(X509Name.C);
            c.ListOidSubject.Add(X509Name.E);
            c.ListOidSubject.Add(X509Name.OU);
            c.ListOidSubject.Add(X509Name.OU);
            //adicionar quantos OU forem necessários
            c.ListOidSubject.Add(Org.BouncyCastle.Asn1.X509.X509Name.CN);

            c.ListValuesSubject.Add("BR");
            c.ListValuesSubject.Add("Email");
            c.ListValuesSubject.Add("SETOR");
            c.ListValuesSubject.Add("ENTIDADE");
            c.ListValuesSubject.Add("CPF"));
            c.ListValuesSubject.Add("NOME COMPLETO");

            var cert = c.GenerateSelfSignedCertificate(c.ListOidSubject, c.ListValuesSubject, c.ListOidIssuer, c.ListValuesIssuer);
            X509Certificate2UI.DisplayCertificate(cert);
