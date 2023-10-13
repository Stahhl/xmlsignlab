using System.Security.Cryptography;
using System.Xml;
using src;

namespace test;

public class SignTest
{
    private const string Xml =
        """
        <root>
            <creditcard>
                <number>19834209</number>
                <expiry>02/02/2002</expiry>
            </creditcard>
        </root>
        """;

    [Fact]
    public void VerifyWithPublicKeyXml()
    {
        var xmlDoc = new XmlDocument();
        xmlDoc.LoadXml(Xml);
        
        using var rsaBase = RSA.Create();

        var privateKey = rsaBase.ToXmlString(true);
        var publicKey = rsaBase.ToXmlString(false);

        using var rsaSecret = RSA.Create();
        rsaSecret.FromXmlString(privateKey);
        
        Signer.SignXml(xmlDoc, rsaSecret);

        using var rsaPublic = RSA.Create();
        rsaPublic.FromXmlString(publicKey);

        var verified = Verifyer.VerifyXml(xmlDoc, rsaPublic);
        
        Assert.True(verified);
    }
    
    [Fact]
    public void VerifyWithPublicKey()
    {
        var xmlDoc = new XmlDocument();
        xmlDoc.LoadXml(Xml);

        using var rsa1 = RSA.Create();
        
        Signer.SignXml(xmlDoc, rsa1);

        // Get the public key of rsa1
        var rsa1PublicKey = rsa1.ExportParameters(false);
        // Use the public key of rsa1 to generate rsa2
        using var rsa2 = RSA.Create();
        rsa2.ImportParameters(rsa1PublicKey);
        
        var verified = Verifyer.VerifyXml(xmlDoc, rsa2);
        
        Assert.True(verified);
    }
    
    [Fact]
    public void VerifyWithDifferentKey()
    {
        var xmlDoc = new XmlDocument();
        xmlDoc.LoadXml(Xml);

        using var rsa1 = RSA.Create();
        using var rsa2 = RSA.Create();
        
        Signer.SignXml(xmlDoc, rsa1);

        var verified = Verifyer.VerifyXml(xmlDoc, rsa2);
        
        Assert.False(verified);
    }
    
    [Fact]
    public void VerifyWithSameKey()
    {
        var xmlDoc = new XmlDocument();
        xmlDoc.LoadXml(Xml);

        using var rsa = RSA.Create();
        
        Signer.SignXml(xmlDoc, rsa);

        var verified = Verifyer.VerifyXml(xmlDoc, rsa);
        
        Assert.True(verified);
    }
}