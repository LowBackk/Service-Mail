using System.Security.Claims;
using System.Text;
using System.Net.Mail;
using System.Net;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Secret;
using MailNamespace;
using System.Text.Json;




Mail mail = new();
secretKey sec = new();
mailAuth mailAuth = new();
secretAdminToken adminSec = new();
discordWebhook discordWebhook = new();
var builder = WebApplication.CreateBuilder(args);
var MyAllowSpecificOrigins = "_myAllowSpecificOrigins";
builder.Services.AddCors(options =>
{
  options.AddPolicy(name: MyAllowSpecificOrigins,
    builder =>
      {
        builder.WithOrigins("*");
      });
});

var app = builder.Build();

app.UseCors(MyAllowSpecificOrigins);

var smtpClient = new SmtpClient("smtp.gmail.com")
{
  Port = 587,
  Credentials = new NetworkCredential(mailAuth.mail, mailAuth.password),
  EnableSsl = true,
};



app.MapGet("/{token}", async (HttpContext httpContext, string token) =>
{
  var body = ValidateJwtToken(token);
  Console.Write(JsonSerializer.Serialize(body));
  if (body == null) { return Results.Unauthorized(); }

  try
  {
    MailMessage mail = new MailMessage
    {
      From = new MailAddress($"Lowback <{mailAuth.mail}>"),
      Subject = body.Subject!,
      Body = body.Content!,
      IsBodyHtml = false
    };

    mail.To.Add(new MailAddress(body.Recipient!));

    smtpClient.Send(mail);

    await SendDiscordNotification(body.Recipient!, body.Subject!);
  }
  catch (Exception e) { return Results.Problem(e.Message); }
  return Results.Ok(new { Message = "Mail send" });
});

app.Run("http://localhost:62703");




JwtUser? ValidateJwtToken(string token)
{
  var tokenHandler = new JwtSecurityTokenHandler();
  var key = Encoding.UTF8.GetBytes(adminSec.key); // Ensure `adminSec.key` is a valid secret key string.

  try
  {
    var principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
    {
      ValidateIssuer = false, // Ignore issuer validation
      ValidateAudience = false, // Ignore audience validation
      ValidateLifetime = false, // Ignore expiration time validation
      ValidateIssuerSigningKey = true, // Ensure token is signed correctly
      IssuerSigningKey = new SymmetricSecurityKey(key)
    }, out SecurityToken validatedToken);

    var jwtToken = validatedToken as JwtSecurityToken;

    // Ensure token has claims (i.e., content in the body)
    if (jwtToken == null || !jwtToken.Claims.Any())
      return null; // Invalid token (empty claims)

    var requiredClaims = new[] { "recipient", "content", "subject" };

    if (!requiredClaims.All(c => jwtToken.Claims.Any(claim => claim.Type == c)))
      return null;

    var user = new JwtUser
    {
      Subject = jwtToken.Claims.FirstOrDefault(c => c.Type == "subject")?.Value,
      Content = jwtToken.Claims.FirstOrDefault(c => c.Type == "content")?.Value,
      Recipient = jwtToken.Claims.FirstOrDefault(c => c.Type == "recipient")?.Value
    };

    return user;
  }
  catch
  {
    return null; // Token is invalid
  }
}

async Task SendDiscordNotification(string recipient, string subject)
{
  string webhookUrl = discordWebhook.url;

  using (HttpClient httpClient = new HttpClient())
  {
    var payload = new
    {
      content = $"📧 **Email Sent!**\n**Recipient:** {recipient}\n**Subject:** {subject}"
    };

    var jsonPayload = JsonSerializer.Serialize(payload);
    var content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");

    await httpClient.PostAsync(webhookUrl, content);
  }
}

public class JwtUser
{
  public string? Subject { get; set; }
  public string? Content { get; set; }
  public string? Recipient { get; set; }
}

