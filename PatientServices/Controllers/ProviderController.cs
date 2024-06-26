﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using HealthServices.Data;
using PatientServices.Models.Provider;
using PatientServices.Services.Interfaces;

namespace PatientServices.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class ProviderController : ControllerBase
    {
        private readonly IProviderService _providerService;

        public ProviderController(IProviderService providerService)
        {
            _providerService = providerService;
        }

        // GET: api/Providers
        [HttpGet("GetAllProviders")]
        public async Task<ActionResult<IEnumerable<Provider>>> GetProviders()
        {
            try
            {
                var providers = await _providerService.GetProvidersAsync();
                return Ok(providers);
            }
            catch (Exception ex)
            {
                // Log the exception or handle it in some other way
                return StatusCode(500, "An error occurred while processing your request.");
            }
        }

        // GET: api/Providers/5
        [HttpGet("GetProviderById/{id}")]
        public async Task<ActionResult<Provider>> GetProvider(int id)
        {
            try
            {
                var provider = await _providerService.GetProviderByIdAsync(id);
                if (provider == null)
                {
                    return NotFound();
                }
                return Ok(provider);
            }
            catch (Exception ex)
            {
                // Log the exception or handle it in some other way
                return StatusCode(500, "An error occurred while processing your request.");
            }
        }

        // PUT: api/Providers/5
        [HttpPut("UpdateProvider/{id}")]
        public async Task<IActionResult> PutProvider(int id, Provider provider)
        {
            try
            {
                if (id != provider.ProviderId)
                {
                    return BadRequest();
                }
                await _providerService.UpdateProviderAsync(provider);
                return NoContent();
            }
            catch (Exception ex)
            {
                // Log the exception or handle it in some other way
                return StatusCode(500, "An error occurred while processing your request.");
            }
        }

        // POST: api/Providers
        [HttpPost("CreateProvider")]
        public async Task<ActionResult<Provider>> PostProvider(Provider provider)
        {
            try
            {
                await _providerService.AddProviderAsync(provider);
                return CreatedAtAction(nameof(GetProvider), new { id = provider.ProviderId }, provider);
            }
            catch (Exception ex)
            {
                // Log the exception or handle it in some other way
                return StatusCode(500, "An error occurred while processing your request.");
            }
        }

        // DELETE: api/Providers/5
        [HttpDelete("DeleteProvider/{id}")]
        public async Task<IActionResult> DeleteProvider(int id)
        {
            try
            {
                if (!_providerService.ProviderExists(id))
                {
                    return NotFound();
                }
                await _providerService.DeleteProviderAsync(id);
                return NoContent();
            }
            catch (Exception ex)
            {
                // Log the exception or handle it in some other way
                return StatusCode(500, "An error occurred while processing your request.");
            }
        }
    }

}
