package com.controllers;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.naming.NamingException;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import com.ejbs.AuthenticationRemote;
import com.entities.Utilisateur;
import com.models.JsonResult;
import com.models.UtilisationToken;

import com.security.JwtSecurity;
import com.utilities.EmailSender;
import com.utilities.Utilities;

import org.mindrot.jbcrypt.BCrypt;

@Stateless
@Path("/auth")
public class AuthenticationController {

	@EJB(lookup = "ejb:/HotelBookersEJB//Authentication!com.ejbs.AuthenticationRemote")
	private AuthenticationRemote authenticationRemote;
	private JwtSecurity secur = new JwtSecurity();

	@Path("/register")
	@POST
	@Produces("application/json")
	public JsonResult register(@FormParam("nom") String nom, @FormParam("prenom") String prenom,
			@FormParam("adresse") String adresse, @FormParam("ville") String ville, @FormParam("region") String region,
			@FormParam("codePostal") String codePostal, @FormParam("sexe") String sexe,
			@FormParam("numTel") String numTel, @FormParam("email") String email, @FormParam("password") String pwd) {
		if (nom == null || prenom == null || prenom == null || adresse == null || ville == null || region == null
				|| codePostal == null || sexe == null || email == null || pwd == null || nom.isEmpty()
				|| prenom.isEmpty() || prenom.isEmpty() || adresse.isEmpty() || ville.isEmpty() || region.isEmpty()
				|| codePostal.isEmpty() || sexe.isEmpty() || email.isEmpty() || pwd.isEmpty())
			return new JsonResult(401, "Veuillez remplir correctement tous les champs");

		try {
			if(authenticationRemote.registerUser(nom,prenom,adresse,ville,region,codePostal,sexe,numTel,email,pwd,"ROLE_USER")) {
				String [] from= {email};

				String [] cc= {"abdelkarim.drareni@gmail.com"};
				String message = "<p style=\"text-align: center;\"><span style=\"color: #ff0000; font-size: 14pt;\">Cher Client PYRAMID<span id=\"spans0e0\" class=\"ac\">,</span></span></p>\n" + 
						"<p><br />Vous venez de vous inscrire <span id=\"spans1e0\" class=\"ac\">&agrave;</span> la plateforme de Reservation de chambre d'<span id=\"spans1e1\" class=\"sac\">h&ocirc;tels</span> <strong>PYRAMID</strong><span id=\"spans1e2\" class=\"ac\">,</span></p>\n" + 
						"<p>L'<span id=\"spans2e0\" class=\"sac\">&eacute;quipe</span> <strong>PYRAMID</strong> vous remercie de votre confiance et vous souhaite de <span id=\"spans2e1\" class=\"ac\">passer</span> d'agr&eacute;able s&eacute;jour dans l'une des chambres de la chaine <strong>PYRAMID</strong></p>\n" + 
						"<p>Cordialement l'&eacute;quipe <strong>PYRAMID</strong>.</p>";
				
				try {
					EmailSender.sendMail
					("Confirmation Inscription Client",message,from ,cc );
				} catch (NamingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				return new JsonResult(201,"inscription reussi");
			}
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return new JsonResult(401, "email deja utilise, veuillez vous authentifier !");
	}

	@Path("/login")
	@POST
	@Produces("application/json")
	public JsonResult login(@FormParam("email") String username, @FormParam("password") String password) {
		if (username == null || password == null || username.isEmpty() || password.isEmpty())
			return new JsonResult(401, "Tous les champs doivent etre précisés");
		Utilisateur util = null;
		try {
			
			System.out.println("Inside try catch");
			util = authenticationRemote.validUser(username, password);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		if (util != null) {
			return new JsonResult(201,
					new UtilisationToken(util, secur.createToken("Authentication", util.getId().toString())));
		} else {
			return new JsonResult(401, "user not register! please register");
		}

	}

	@GET
	@Path("/passwordLost/{email}")
	@Produces("application/json")
	public JsonResult passwordLost(@PathParam("email") String email) {
		JsonResult jsonResult;
		if (email.isEmpty()) {
			jsonResult = new JsonResult(401, "l'adresse email doit etre rempli");
		}
		if (!authenticationRemote.emailExists(email)) {
			jsonResult = new JsonResult(401, "vous n'etes pas inscrit, veuillez vous inscrire");
			return jsonResult;
		}
		Utilisateur u = authenticationRemote.getUserFormEmail(email);
		
		if (u != null) {
			String newPassword = Utilities.randomString(6);
			boolean success = false;
			try {
				success = authenticationRemote.updateUserPassword(u.getId(),newPassword);
			} catch (NoSuchAlgorithmException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (InvalidKeySpecException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			
			
			if (!success) {
				jsonResult = new JsonResult(401, "Une erreure est sourvenue !");
				return jsonResult;
			}
			
			
			String[] from = { u.getEmail() };

			String[] cc = { "abdelkarim.drareni@gmail.com" };
			String message = "<p style=\"text-align: center;\"><strong><span style=\"color: #ff0000;\"><span style=\"font-size: 18pt;\">Cher client Pyramide</span>,</span></strong></p>\n"
					+ "<p>Vous avez fait une demande d'envoi de votre mot de passe, suite <span id=\"spans1e0\" class=\"ac\">&agrave;</span> l'<span id=\"spans1e1\" class=\"ac\">oubli</span> de ce dernier,</p>\n"
					+ "<p>Voici votre identifiant et votre mot de passe :</p>\n"
					+ "<p>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Email: " + u.getEmail() + "</p>\n"
					+ "<p>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Mot de passe :" + newPassword + "</p>\n"
					+ "<p>Si vous <span id=\"spans2e0\" class=\"ac\">n'&ecirc;tes</span> pas l'auteur de cette demande, on vous invite <span id=\"spans2e1\" class=\"ac\">&agrave;</span> changer votre mot de passe et <span id=\"spans2e2\" class=\"ac\">&agrave;</span> nous signaler le <span id=\"spans2e3\" class=\"sac\">probl&egrave;me</span> en nous contactant.</p>\n"
					+ "<p><span style=\"color: #000000;\">En vous remerciant par avance, nous vous adressons,&nbsp;<span class=\"m_-6904676539164650241orange1\">Madame/Monsieur</span>, nos salutations distingu&eacute;es,</span></p>\n"
					+ "<p><span style=\"color: #333333;\"><em>Nous vous souhaitons un agr&eacute;able s&eacute;jour,<br /> Votre &eacute;quipe Pyramide.</em></span></p>";

			try {
				EmailSender.sendMail("Mot de passe oublie", message, from, cc);

			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			jsonResult = new JsonResult(201, "Un email vient de vous etre envoyer");
			return jsonResult;
		} else {
			return new JsonResult(401, "erreur lors de l'envoi du mail,  veuillez reessayer");
		}
	}
	

	@Path("/getHash/{value}")
	@GET
	@Produces("application/json")
	public JsonResult getHash(@PathParam("value") String value) {
		JsonResult jsonResult;
		String hashed = "";
		if (value.isEmpty()) {
			jsonResult = new JsonResult(401, "le text a hash� doit etre fourni");
		}
		try {
			hashed = authenticationRemote.hashValue(value);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return new JsonResult(201,hashed);
	}

}
