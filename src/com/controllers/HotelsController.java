package com.controllers;

import java.util.ArrayList;
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;

import com.ejbs.BookingRemote;
import com.ejbs.HotelsRemote;
import com.entities.Chambre;
import com.models.ChambreModel;
import com.models.JsonResult;
import com.utilities.JpaPojoConverter;
import com.utilities.Util;

@Stateless
@Path("/hotels")
public class HotelsController {

	@EJB(lookup ="ejb:/HotelBookersEJB//Hotels!com.ejbs.HotelsRemote")
    private HotelsRemote hotelsRemote;
	@EJB(lookup ="ejb:/HotelBookersEJB//Booking!com.ejbs.BookingRemote")
	public BookingRemote bookingRemote;
	
	@GET
	@Path("/room/search")
	@Produces("application/json")
	public JsonResult getAllRooms()
    {
		long errCode=201;
		Object result;
		JsonResult jsonResult;
		List<Chambre> listChambres = hotelsRemote.getALlRooms();
		if(listChambres.isEmpty()) {
			errCode = 401;
			result = new String("Aucune chambre n'a ete trouver");
			jsonResult = new JsonResult(errCode,result);
			return jsonResult;
		}	
		
		List<ChambreModel> chambreModelList = new ArrayList();
		ChambreModel chambreModel;
		
		for(Chambre chambre : listChambres ) {
			chambreModel = JpaPojoConverter.chambreJpaToPojo(chambre);
			chambreModelList.add(chambreModel);
		}
		jsonResult = new JsonResult(errCode,chambreModelList);
		return jsonResult;
    }
		
	@GET
	@Path("/room/search/{ville}/{dateDeb}/{dateFin}/{nbAdulte}/{nbEnfant}")
	@Produces("application/json")
	public JsonResult getRoomsWithFilter(
			@PathParam("ville") String ville,
			@PathParam("dateDeb") String dateDeb,
			@PathParam("dateFin") String dateFin,

			@DefaultValue("-1") @PathParam("nbEnfant") int nbEnfant,
			@DefaultValue("-1") @PathParam("nbAdulte") int nbAdulte)
    {
		
		if(ville==null||dateDeb==null || dateFin ==null ||nbEnfant==-1 || nbAdulte==-1
				||ville.isEmpty()||dateDeb.isEmpty() || dateFin.isEmpty())
					return new JsonResult(401, "Tous les champs doivent etre précisés");
		if(!Util.isDateDebGreaterThenDateFin(dateDeb, dateFin))
			return new JsonResult(401, "La date de debut doit etre inferieur a la date de fin");
		
		long errCode=201;
		Object result;
		JsonResult jsonResult;
		List<Chambre> listChambres = hotelsRemote.getRoomsForFilter(ville, dateDeb, dateFin, nbAdulte, nbEnfant);
			
		
		List<ChambreModel> chambreModelList = new ArrayList();
		ChambreModel chambreModel;
		
		for(Chambre chambre : listChambres ) {
			if(bookingRemote.isRoomAvailableForPeriod(chambre.getId(),dateDeb,dateFin)) {
				chambreModel = JpaPojoConverter.chambreJpaToPojo(chambre);
				chambreModelList.add(chambreModel);
			}
			
		}
		if(chambreModelList.isEmpty()) {
			errCode = 401;
			result = new String("Aucune chambre n'a ete trouver");
			jsonResult = new JsonResult(errCode,result);
			return jsonResult;
		}
		jsonResult = new JsonResult(errCode,chambreModelList);
		return jsonResult;
    }
	

}
