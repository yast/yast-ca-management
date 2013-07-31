# encoding: utf-8

# ***************************************************************************
#
# Copyright (c) 2004 - 2012 Novell, Inc.
# All Rights Reserved.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2 of the GNU General Public License as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.   See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, contact Novell, Inc.
#
# To contact Novell about this file by physical or electronic mail,
# you may find current contact information at www.novell.com
#
# ***************************************************************************

#
# File:
#   new_cert_read_write.ycp
#
# Module:
#   CA Management
#
# Summary:
#   Reading default settings; Generating CA/Request/Certificat
#
# Authors:
#   Stefan Schubert <schubi@suse.de>
#
# $Id$
#
# Creating a new CA/Certificate
#
module Yast
  module CaManagementNewCertReadWriteInclude
    def initialize_ca_management_new_cert_read_write(include_target)
      Yast.import "UI"

      textdomain "ca-management"

      Yast.import "CaMgm"
      Yast.import "Popup"
      Yast.import "Timezone"
      Yast.import "YaPI::CaManagement"

      Yast.include include_target, "ca-management/util.rb"
    end

    # Values initializing for creating CA/Certificate/Request
    # @param [String] kind ("Root CA","Sub CA","Client Certificate","Server Certificate","Client Request","Server Request", "Sub CA Request")
    # @return `next
    def new_cert_init(kind)
      CaMgm.emailList = []
      CaMgm.commonName = ""
      CaMgm.CAName = ""
      CaMgm.organisation = ""
      CaMgm.organisationUnit = ""
      CaMgm.locality = ""
      CaMgm.state = ""
      CaMgm.country = "GB"
      CaMgm.password = ""
      CaMgm.verifyPassword = ""
      CaMgm.keyLength = 1024
      CaMgm.validPeriod = 365
      CaMgm.adv_cri_ca = false
      CaMgm.adv_ca = "none"
      CaMgm.adv_pathlen = false
      CaMgm.adv_pathlenValue = 1
      CaMgm.adv_cri_distribution_point = false
      CaMgm.adv_distribution_point = ""
      CaMgm.adv_challenge_password = ""
      CaMgm.adv_cri_issuer_alt_name = false
      CaMgm.adv_copy_issuer_alt_name = false
      CaMgm.adv_copy_issuer_alt_name_enabled = false
      CaMgm.adv_issuer_alt_name_list = []
      CaMgm.adv_cri_key_usage = false
      CaMgm.adv_digitalSignature = false
      CaMgm.adv_nonRepudiation = false
      CaMgm.adv_cRLSign = false
      CaMgm.adv_keyEncipherment = false
      CaMgm.adv_dataEncipherment = false
      CaMgm.adv_encipherOnly = false
      CaMgm.adv_keyAgreement = false
      CaMgm.adv_keyCertSign = false
      CaMgm.adv_decipherOnly = false
      CaMgm.adv_cri_nsComment = false
      CaMgm.adv_nsComment = ""
      CaMgm.adv_cri_nsCertType = false
      CaMgm.adv_client = false
      CaMgm.adv_server = false
      CaMgm.adv_sslCA = false
      CaMgm.adv_email = false
      CaMgm.adv_reserved = false
      CaMgm.adv_emailCA = false
      CaMgm.adv_objsign = false
      CaMgm.adv_objCA = false
      CaMgm.adv_cri_nsSslServerName = false
      CaMgm.adv_nsSslServerName = ""
      CaMgm.adv_cri_subject_alt_name = false
      CaMgm.adv_copy_subject_alt_name = false
      CaMgm.adv_subject_alt_name_list = []
      CaMgm.adv_unstructured_name = ""
      CaMgm.exp_cri_subjectKeyIdentifier = false
      CaMgm.exp_subjectKeyIdentifier = ""
      CaMgm.exp_cri_authorityKeyIdentifier = false
      CaMgm.exp_authorityKeyIdentifier = ""
      CaMgm.exp_cri_netscape_nsBaseUrl = false
      CaMgm.exp_netscape_nsBaseUrl = ""
      CaMgm.exp_cri_netscape_nsRevocationUrl = false
      CaMgm.exp_netscape_nsRevocationUrl = ""
      CaMgm.exp_cri_netscape_nsCaRevocationUrl = false
      CaMgm.exp_netscape_nsCaRevocationUrl = ""
      CaMgm.exp_cri_netscape_nsRenewalUrl = false
      CaMgm.exp_netscape_nsRenewalUrl = ""
      CaMgm.exp_cri_netscape_nsCaPolicyUrl = false
      CaMgm.exp_netscape_nsCaPolicyUrl = ""
      CaMgm.exp_cri_authorityInfoAccess = false
      CaMgm.exp_authorityInfoAccess = ""
      CaMgm.exp_cri_extendedKeyUsage = false
      CaMgm.exp_extendedKeyUsage = ""

      ret = nil
      sdummy = nil
      dummy = nil

      if kind == "Root CA"
        CaMgm.currentCA = "" # sign that a root CA will be created.

        ret = YaPI::CaManagement.ReadCertificateDefaults({ "certType" => "ca" })
        Builtins.y2milestone(
          "ReadCertificateDefaults(%1): %2",
          { "certType" => "ca" },
          ret
        )
      end
      if kind == "Sub CA" || kind == "Sub CA Request"
        ret = YaPI::CaManagement.ReadCertificateDefaults(
          {
            "caName"   => CaMgm.currentCA,
            "caPasswd" => getPassword(CaMgm.currentCA),
            "certType" => "ca"
          }
        )
        Builtins.y2milestone(
          "ReadCertificateDefaults(%1): %2",
          { "caName" => CaMgm.currentCA, "certType" => "ca" },
          ret
        )
      end
      if kind == "Server Certificate" || kind == "Server Request"
        ret = YaPI::CaManagement.ReadCertificateDefaults(
          {
            "caName"   => CaMgm.currentCA,
            "caPasswd" => getPassword(CaMgm.currentCA),
            "certType" => "server"
          }
        )
        Builtins.y2milestone(
          "ReadCertificateDefaults(%1): %2",
          { "caName" => CaMgm.currentCA, "certType" => "server" },
          ret
        )
      end
      if kind == "Client Certificate" || kind == "Client Request"
        ret = YaPI::CaManagement.ReadCertificateDefaults(
          {
            "caName"   => CaMgm.currentCA,
            "caPasswd" => getPassword(CaMgm.currentCA),
            "certType" => "client"
          }
        )
        Builtins.y2milestone(
          "ReadCertificateDefaults(%1): %2",
          { "caName" => CaMgm.currentCA, "certType" => "client" },
          ret
        )
      end
      if ret == nil
        showErrorCaManagement
        return :next
      end

      if kind == "Sub CA Request" || kind == "Server Request" ||
          kind == "Client Request"
        # no authorityInfoAccess
        CaMgm.exp_cri_authorityInfoAccess = false
        CaMgm.exp_authorityInfoAccess = ""
      end

      CaMgm.keyLength = Builtins.tointeger(
        Ops.get_string(ret, "keyLength", "0")
      )
      CaMgm.validPeriod = Builtins.tointeger(Ops.get_string(ret, "days", "0"))

      dn = Ops.get_map(ret, "DN", {})
      CaMgm.organisation = Ops.get_string(Ops.get(dn, "O", []), 0, "")
      CaMgm.organisationUnit = Ops.get_string(Ops.get(dn, "OU", []), 0, "")
      CaMgm.locality = Ops.get_string(Ops.get(dn, "L", []), 0, "")
      CaMgm.state = Ops.get_string(Ops.get(dn, "ST", []), 0, "")
      CaMgm.country = Ops.get_string(Ops.get(dn, "C", []), 0) do
        Timezone.GetCountryForTimezone("")
      end

      sdummy = Ops.get_string(ret, "basicConstraints", "")
      if sdummy != nil
        dummy = Builtins.splitstring(sdummy, ",")
      else
        dummy = []
      end
      Builtins.foreach(dummy) do |entry|
        entry = strip(entry)
        valuelist = Builtins.splitstring(entry, ":")
        ident = strip(Ops.get_string(valuelist, 0, ""))
        value = strip(Ops.get_string(valuelist, 1, ""))
        CaMgm.adv_cri_ca = true if ident == "critical"
        if ident == "CA"
          if value == "false" || value == "FALSE"
            CaMgm.adv_ca = Ops.add(ident, ":false")
          else
            CaMgm.adv_ca = Ops.add(ident, ":true")
          end
        end
        if ident == "pathlen"
          CaMgm.adv_pathlen = true
          CaMgm.adv_pathlenValue = Builtins.tointeger(value)
        end
      end

      sdummy = Ops.get_string(ret, "crlDistributionPoints", "")
      if sdummy != nil
        dummy = Builtins.splitstring(sdummy, ",")
      else
        dummy = []
      end
      Builtins.foreach(dummy) do |entry|
        entry = strip(entry)
        if entry == "critical"
          CaMgm.adv_cri_distribution_point = true
        else
          CaMgm.adv_distribution_point = entry
        end
      end

      sdummy = Ops.get_string(ret, "issuerAltName", "")
      if sdummy != nil
        dummy = Builtins.splitstring(sdummy, ",")
      else
        dummy = []
      end
      Builtins.foreach(dummy) do |entry|
        entry = strip(entry)
        valuelist = Builtins.splitstring(entry, ":")
        ident = strip(Ops.get_string(valuelist, 0, ""))
        value = strip(Ops.get_string(valuelist, 1, ""))
        if ident == "critical"
          CaMgm.adv_cri_issuer_alt_name = true
        elsif ident == "issuer" && value == "copy"
          CaMgm.adv_copy_issuer_alt_name = true
        else
          new_entry = {}
          Ops.set(new_entry, "kind", ident)
          Ops.set(new_entry, "name", value)
          CaMgm.adv_issuer_alt_name_list = Builtins.add(
            CaMgm.adv_issuer_alt_name_list,
            new_entry
          )
        end
      end

      sdummy = Ops.get_string(ret, "keyUsage", "")
      if sdummy != nil
        dummy = Builtins.splitstring(sdummy, ",")
      else
        dummy = []
      end
      Builtins.foreach(dummy) do |entry|
        entry = strip(entry)
        if entry == "critical"
          CaMgm.adv_cri_key_usage = true
        elsif entry == "digitalSignature"
          CaMgm.adv_digitalSignature = true
        elsif entry == "nonRepudiation"
          CaMgm.adv_nonRepudiation = true
        elsif entry == "cRLSign"
          CaMgm.adv_cRLSign = true
        elsif entry == "keyEncipherment"
          CaMgm.adv_keyEncipherment = true
        elsif entry == "dataEncipherment"
          CaMgm.adv_dataEncipherment = true
        elsif entry == "encipherOnly"
          CaMgm.adv_encipherOnly = true
        elsif entry == "keyAgreement"
          CaMgm.adv_keyAgreement = true
        elsif entry == "keyCertSign"
          CaMgm.adv_keyCertSign = true
        elsif entry == "decipherOnly"
          CaMgm.adv_decipherOnly = true
        end
      end

      sdummy = Ops.get_string(ret, "nsComment", "")
      if sdummy != nil
        dummy = Builtins.splitstring(sdummy, ",")
      else
        dummy = []
      end
      Builtins.foreach(dummy) do |entry|
        entry = strip(entry)
        if entry == "critical"
          CaMgm.adv_cri_nsComment = true
        else
          CaMgm.adv_nsComment = entry
        end
      end

      sdummy = Ops.get_string(ret, "nsCertType", "")
      if sdummy != nil
        dummy = Builtins.splitstring(sdummy, ",")
      else
        dummy = []
      end
      Builtins.foreach(dummy) do |entry|
        entry = strip(entry)
        if entry == "critical"
          CaMgm.adv_cri_nsCertType = true
        elsif entry == "client"
          CaMgm.adv_client = true
        elsif entry == "server"
          CaMgm.adv_server = true
        elsif entry == "sslCA"
          CaMgm.adv_sslCA = true
        elsif entry == "email"
          CaMgm.adv_email = true
        elsif entry == "reserved"
          CaMgm.adv_reserved = true
        elsif entry == "emailCA"
          CaMgm.adv_emailCA = true
        elsif entry == "objsign"
          CaMgm.adv_objsign = true
        elsif entry == "objCA"
          CaMgm.adv_objCA = true
        end
      end

      sdummy = Ops.get_string(ret, "nsSslServerName", "")
      if sdummy != nil
        dummy = Builtins.splitstring(sdummy, ",")
      else
        dummy = []
      end
      Builtins.foreach(dummy) do |entry|
        entry = strip(entry)
        if entry == "critical"
          CaMgm.adv_cri_nsSslServerName = true
        else
          CaMgm.adv_nsSslServerName = entry
        end
      end

      sdummy = Ops.get_string(ret, "subjectAltName", "")
      if sdummy != nil
        dummy = Builtins.splitstring(sdummy, ",")
      else
        dummy = []
      end
      Builtins.foreach(dummy) do |entry|
        entry = strip(entry)
        valuelist = Builtins.splitstring(entry, ":")
        ident = strip(Ops.get_string(valuelist, 0, ""))
        value = strip(Ops.get_string(valuelist, 1, ""))
        if ident == "critical"
          CaMgm.adv_cri_subject_alt_name = true
        elsif ident == "email" && value == "copy"
          CaMgm.adv_copy_subject_alt_name = true
        else
          new_entry = {}
          Ops.set(new_entry, "kind", ident)
          Ops.set(new_entry, "name", value)
          CaMgm.adv_subject_alt_name_list = Builtins.add(
            CaMgm.adv_subject_alt_name_list,
            new_entry
          )
        end
      end

      sdummy = Ops.get_string(ret, "subjectKeyIdentifier", "")
      if sdummy != nil
        dummy = Builtins.splitstring(sdummy, ",")
      else
        dummy = []
      end
      Builtins.foreach(dummy) do |entry|
        entry = strip(entry)
        if entry == "critical"
          CaMgm.exp_cri_subjectKeyIdentifier = true
        else
          CaMgm.exp_subjectKeyIdentifier = entry
        end
      end

      sdummy = Ops.get_string(ret, "authorityKeyIdentifier", "")
      if sdummy != nil
        dummy = Builtins.splitstring(sdummy, ",")
      else
        dummy = []
      end
      counter = 0
      Builtins.foreach(dummy) do |entry|
        entry = strip(entry)
        valuelist = Builtins.splitstring(entry, ":")
        ident = strip(Ops.get_string(valuelist, 0, ""))
        value = strip(Ops.get_string(valuelist, 1, ""))
        if ident == "critical"
          CaMgm.exp_cri_authorityKeyIdentifier = true
        else
          if counter == 0
            CaMgm.exp_authorityKeyIdentifier = Ops.add(
              Ops.add(
                Ops.add(CaMgm.exp_authorityKeyIdentifier, ident),
                Ops.greater_than(Builtins.size(value), 0) ? ":" : ""
              ),
              value
            )
          else
            CaMgm.exp_authorityKeyIdentifier = Ops.add(
              Ops.add(
                Ops.add(Ops.add(CaMgm.exp_authorityKeyIdentifier, ","), ident),
                Ops.greater_than(Builtins.size(value), 0) ? ":" : ""
              ),
              value
            )
          end
          counter = Ops.add(counter, 1)
        end
      end

      sdummy = Ops.get_string(ret, "nsBaseUrl", "")
      if sdummy != nil
        dummy = Builtins.splitstring(sdummy, ",")
      else
        dummy = []
      end
      Builtins.foreach(dummy) do |entry|
        entry = strip(entry)
        if entry == "critical"
          CaMgm.exp_cri_netscape_nsBaseUrl = true
        else
          CaMgm.exp_netscape_nsBaseUrl = entry
        end
      end

      sdummy = Ops.get_string(ret, "nsRevocationUrl", "")
      if sdummy != nil
        dummy = Builtins.splitstring(sdummy, ",")
      else
        dummy = []
      end
      Builtins.foreach(dummy) do |entry|
        entry = strip(entry)
        if entry == "critical"
          CaMgm.exp_cri_netscape_nsRevocationUrl = true
        else
          CaMgm.exp_netscape_nsRevocationUrl = entry
        end
      end

      sdummy = Ops.get_string(ret, "nsCaRevocationUrl", "")
      if sdummy != nil
        dummy = Builtins.splitstring(sdummy, ",")
      else
        dummy = []
      end
      Builtins.foreach(dummy) do |entry|
        entry = strip(entry)
        if entry == "critical"
          CaMgm.exp_cri_netscape_nsCaRevocationUrl = true
        else
          CaMgm.exp_netscape_nsCaRevocationUrl = entry
        end
      end

      sdummy = Ops.get_string(ret, "nsRenewalUrl", "")
      if sdummy != nil
        dummy = Builtins.splitstring(sdummy, ",")
      else
        dummy = []
      end
      Builtins.foreach(dummy) do |entry|
        entry = strip(entry)
        if entry == "critical"
          CaMgm.exp_cri_netscape_nsRenewalUrl = true
        else
          CaMgm.exp_netscape_nsRenewalUrl = entry
        end
      end

      sdummy = Ops.get_string(ret, "nsCaPolicyUrl", "")
      if sdummy != nil
        dummy = Builtins.splitstring(sdummy, ",")
      else
        dummy = []
      end
      Builtins.foreach(dummy) do |entry|
        entry = strip(entry)
        if entry == "critical"
          CaMgm.exp_cri_netscape_nsCaPolicyUrl = true
        else
          CaMgm.exp_netscape_nsCaPolicyUrl = entry
        end
      end

      sdummy = Ops.get_string(ret, "authorityInfoAccess", "")
      if sdummy != nil
        dummy = Builtins.splitstring(sdummy, ",")
      else
        dummy = []
      end
      counter = 0
      Builtins.foreach(dummy) do |entry|
        entry = strip(entry)
        valuelist = Builtins.splitstring(entry, ":")
        ident = strip(Ops.get_string(valuelist, 0, ""))
        value = strip(Ops.get_string(valuelist, 1, ""))
        if ident == "critical"
          CaMgm.exp_cri_authorityInfoAccess = true
        else
          if counter == 0
            CaMgm.exp_authorityInfoAccess = Ops.add(
              Ops.add(
                Ops.add(CaMgm.exp_authorityInfoAccess, ident),
                Ops.greater_than(Builtins.size(value), 0) ? ":" : ""
              ),
              value
            )
          else
            CaMgm.exp_authorityInfoAccess = Ops.add(
              Ops.add(
                Ops.add(Ops.add(CaMgm.exp_authorityInfoAccess, ","), ident),
                Ops.greater_than(Builtins.size(value), 0) ? ":" : ""
              ),
              value
            )
          end
          counter = Ops.add(counter, 1)
        end
      end

      sdummy = Ops.get_string(ret, "extendedKeyUsage", "")
      if sdummy != nil
        dummy = Builtins.splitstring(sdummy, ",")
      else
        dummy = []
      end
      counter = 0
      Builtins.foreach(dummy) do |entry|
        entry = strip(entry)
        valuelist = Builtins.splitstring(entry, ":")
        ident = strip(Ops.get_string(valuelist, 0, ""))
        value = strip(Ops.get_string(valuelist, 1, ""))
        if ident == "critical"
          CaMgm.exp_cri_extendedKeyUsage = true
        else
          if counter == 0
            CaMgm.exp_extendedKeyUsage = Ops.add(
              Ops.add(
                Ops.add(CaMgm.exp_extendedKeyUsage, ident),
                Ops.greater_than(Builtins.size(value), 0) ? ":" : ""
              ),
              value
            )
          else
            CaMgm.exp_extendedKeyUsage = Ops.add(
              Ops.add(
                Ops.add(Ops.add(CaMgm.exp_extendedKeyUsage, ","), ident),
                Ops.greater_than(Builtins.size(value), 0) ? ":" : ""
              ),
              value
            )
          end
          counter = Ops.add(counter, 1)
        end
      end

      #evaluate if "Copy Subject Alt Name from CA" is enabled in Issuer Alt Name
      if kind == "Root CA"
        # Root Ca
        # If the own "Subject Alt Name" is defined, the copy will be allowed
        if CaMgm.adv_cri_subject_alt_name || CaMgm.adv_copy_subject_alt_name ||
            Ops.greater_than(Builtins.size(CaMgm.adv_subject_alt_name_list), 0)
          CaMgm.adv_copy_issuer_alt_name_enabled = true
        else
          CaMgm.adv_copy_issuer_alt_name = false
          CaMgm.adv_copy_issuer_alt_name_enabled = false
        end
      else
        # Certificates, Sub-CAs, Requests
        ret2 = Convert.to_map(
          YaPI::CaManagement.ReadCA(
            {
              "caName"   => CaMgm.currentCA,
              "caPasswd" => getPassword(CaMgm.currentCA),
              "type"     => "parsed"
            }
          )
        )
        Builtins.y2milestone("ReadCA(%1): %2", CaMgm.currentCA, ret2)
        if ret2 == nil
          showErrorCaManagement
        else
          opensslExtentions = Ops.get_map(ret2, "OPENSSL_EXTENSIONS", {})
          if Ops.greater_than(
              Builtins.size(
                Ops.get(
                  opensslExtentions,
                  "X509v3 Subject Alternative Name",
                  []
                )
              ),
              0
            )
            # Subject Alternative Name of the "parent" CA is available. So the user
            # can copy it.
            CaMgm.adv_copy_issuer_alt_name_enabled = true
          else
            CaMgm.adv_copy_issuer_alt_name = false
            CaMgm.adv_copy_issuer_alt_name_enabled = false
          end
        end
      end

      :next
    end


    # Creating CA/Certificate or signing a request by calling the CaManagement module
    # @param [String] kind ("Root CA","Sub CA","Client Certificate","Server Certificate", "signRequest", "Sub CA Request")
    # @return true ( success )
    def cert_write(kind)
      param = {}

      # fillup parameters depending on kind

      Ops.set(param, "caName", CaMgm.CAName) if kind == "Root CA"
      if kind == "Server Request" || kind == "Client Request" ||
          kind == "Sub CA Request"
        Ops.set(param, "caName", CaMgm.currentCA)
        Ops.set(param, "caPasswd", getPassword(CaMgm.currentCA))
      end
      if kind == "Server Certificate"
        Ops.set(param, "caName", CaMgm.currentCA)
        Ops.set(param, "certType", "server")
        Ops.set(param, "caPasswd", getPassword(CaMgm.currentCA))
        #param["notext"] = "1";
        Builtins.foreach(CaMgm.prop_subject_alt_name_list) do |elem|
          CaMgm.adv_subject_alt_name_list = Builtins.add(
            CaMgm.adv_subject_alt_name_list,
            elem
          )
        end
        CaMgm.adv_cri_issuer_alt_name = CaMgm.prop_adv_cri_issuer_alt_name
      end
      if kind == "Client Certificate"
        Ops.set(param, "caName", CaMgm.currentCA)
        Ops.set(param, "certType", "client")
        Ops.set(param, "caPasswd", getPassword(CaMgm.currentCA)) 
        #param["notext"] = "1";
      end

      if kind == "Sub CA"
        Ops.set(param, "caName", CaMgm.currentCA)
        Ops.set(param, "newCaName", CaMgm.CAName)
        Ops.set(param, "caPasswd", getPassword(CaMgm.currentCA))
      end

      if kind == "signRequest"
        Ops.set(param, "caName", CaMgm.currentCA)
        Ops.set(param, "request", CaMgm.currentRequest)
        Ops.set(param, "certType", CaMgm.requestKind)
        Ops.set(param, "caPasswd", getPassword(CaMgm.currentCA)) 
        #param["notext"] = "1";
      end

      if kind != "signRequest"
        Ops.set(param, "keyPasswd", CaMgm.password)
        Ops.set(param, "commonName", CaMgm.commonName)

        if Ops.greater_than(Builtins.size(CaMgm.emailList), 0)
          # taking standard EMAIL
          Builtins.foreach(CaMgm.emailList) do |element|
            if Ops.get_boolean(element, "default", false) == true
              Ops.set(
                param,
                "emailAddress",
                Ops.get_string(element, "name", "")
              )
            end
          end
        end

        Ops.set(param, "keyLength", Builtins.tostring(CaMgm.keyLength))
        if Ops.greater_than(Builtins.size(CaMgm.country), 0)
          Ops.set(param, "countryName", CaMgm.country)
        end
        if Ops.greater_than(Builtins.size(CaMgm.state), 0)
          Ops.set(param, "stateOrProvinceName", CaMgm.state)
        end
        if Ops.greater_than(Builtins.size(CaMgm.locality), 0)
          Ops.set(param, "localityName", CaMgm.locality)
        end
        if Ops.greater_than(Builtins.size(CaMgm.organisation), 0)
          Ops.set(param, "organizationName", CaMgm.organisation)
        end
        if Ops.greater_than(Builtins.size(CaMgm.organisationUnit), 0)
          Ops.set(param, "organizationalUnitName", CaMgm.organisationUnit)
        end
        if Ops.greater_than(Builtins.size(CaMgm.adv_challenge_password), 0)
          Ops.set(param, "challengePassword", CaMgm.adv_challenge_password)
        end
        if Ops.greater_than(Builtins.size(CaMgm.adv_unstructured_name), 0)
          Ops.set(param, "unstructuredName", CaMgm.adv_unstructured_name)
        end
      end

      if kind != "Server Request" && kind != "Client Request" &&
          kind != "Sub CA Request"
        Ops.set(param, "days", Builtins.tostring(CaMgm.validPeriod))

        if Ops.greater_than(Builtins.size(CaMgm.exp_authorityKeyIdentifier), 0)
          if CaMgm.exp_cri_authorityKeyIdentifier
            Ops.set(
              param,
              "authorityKeyIdentifier",
              Ops.add("critical,", CaMgm.exp_authorityKeyIdentifier)
            )
          else
            Ops.set(
              param,
              "authorityKeyIdentifier",
              CaMgm.exp_authorityKeyIdentifier
            )
          end
        end
        if Ops.greater_than(Builtins.size(CaMgm.adv_issuer_alt_name_list), 0) ||
            CaMgm.adv_copy_issuer_alt_name
          prevFound = false
          if CaMgm.adv_cri_issuer_alt_name
            Ops.set(param, "issuerAltName", "critical")
            prevFound = true
          else
            Ops.set(param, "issuerAltName", "")
          end
          Builtins.foreach(CaMgm.adv_issuer_alt_name_list) do |element|
            Ops.set(
              param,
              "issuerAltName",
              Ops.add(
                Ops.add(
                  Ops.add(
                    Ops.add(
                      Ops.get_string(param, "issuerAltName", ""),
                      prevFound ? "," : ""
                    ),
                    Ops.get_string(element, "kind", "")
                  ),
                  ":"
                ),
                Ops.get_string(element, "name", "")
              )
            )
            prevFound = true
          end
          if CaMgm.adv_copy_issuer_alt_name
            Ops.set(
              param,
              "issuerAltName",
              Ops.add(
                Ops.add(
                  Ops.get_string(param, "issuerAltName", ""),
                  prevFound ? "," : ""
                ),
                "issuer:copy"
              )
            )
          end
        end
        if Ops.greater_than(Builtins.size(CaMgm.exp_netscape_nsBaseUrl), 0)
          Ops.set(
            param,
            "nsBaseUrl",
            Ops.add(
              CaMgm.exp_cri_netscape_nsBaseUrl ? "critical," : "",
              CaMgm.exp_netscape_nsBaseUrl
            )
          )
        end
        if Ops.greater_than(
            Builtins.size(CaMgm.exp_netscape_nsRevocationUrl),
            0
          )
          Ops.set(
            param,
            "nsRevocationUrl",
            Ops.add(
              CaMgm.exp_cri_netscape_nsRevocationUrl ? "critical," : "",
              CaMgm.exp_netscape_nsRevocationUrl
            )
          )
        end
        if Ops.greater_than(
            Builtins.size(CaMgm.exp_netscape_nsCaRevocationUrl),
            0
          )
          Ops.set(
            param,
            "nsCaRevocationUrl",
            Ops.add(
              CaMgm.exp_cri_netscape_nsCaRevocationUrl ? "critical," : "",
              CaMgm.exp_netscape_nsCaRevocationUrl
            )
          )
        end
        if Ops.greater_than(Builtins.size(CaMgm.exp_netscape_nsRenewalUrl), 0)
          Ops.set(
            param,
            "nsRenewalUrl",
            Ops.add(
              CaMgm.exp_cri_netscape_nsRenewalUrl ? "critical," : "",
              CaMgm.exp_netscape_nsRenewalUrl
            )
          )
        end
        if Ops.greater_than(Builtins.size(CaMgm.exp_netscape_nsCaPolicyUrl), 0)
          Ops.set(
            param,
            "nsCaPolicyUrl",
            Ops.add(
              CaMgm.exp_cri_netscape_nsCaPolicyUrl ? "critical," : "",
              CaMgm.exp_netscape_nsCaPolicyUrl
            )
          )
        end
        if Ops.greater_than(Builtins.size(CaMgm.adv_distribution_point), 0)
          Ops.set(
            param,
            "crlDistributionPoints",
            Ops.add(
              CaMgm.adv_cri_distribution_point ? "critical," : "",
              CaMgm.adv_distribution_point
            )
          )
        end
      end


      # fillup parameters which are equal

      if CaMgm.adv_ca != "none"
        if CaMgm.adv_cri_ca
          Ops.set(param, "basicConstraints", Ops.add("critical,", CaMgm.adv_ca))
        else
          Ops.set(param, "basicConstraints", CaMgm.adv_ca)
        end
      else
        Ops.set(param, "basicConstraints", "critical") if CaMgm.adv_cri_ca
      end
      if CaMgm.adv_pathlen
        Ops.set(
          param,
          "basicConstraints",
          Ops.add(
            Ops.add(Ops.get_string(param, "basicConstraints", ""), ", pathlen:"),
            Builtins.tostring(CaMgm.adv_pathlenValue)
          )
        )
      end
      if CaMgm.adv_cri_nsComment
        Ops.set(param, "nsComment", Ops.add("critical,", CaMgm.adv_nsComment))
      else
        Ops.set(param, "nsComment", CaMgm.adv_nsComment)
      end
      if CaMgm.adv_client || CaMgm.adv_server || CaMgm.adv_sslCA ||
          CaMgm.adv_email ||
          CaMgm.adv_reserved ||
          CaMgm.adv_emailCA ||
          CaMgm.adv_objsign ||
          CaMgm.adv_objCA
        firstHit = false
        if CaMgm.adv_client
          Ops.set(param, "nsCertType", "client")
          firstHit = true
        end
        if CaMgm.adv_server
          if firstHit
            Ops.set(
              param,
              "nsCertType",
              Ops.add(Ops.get_string(param, "nsCertType", ""), ",server")
            )
          else
            Ops.set(
              param,
              "nsCertType",
              Ops.add(Ops.get_string(param, "nsCertType", ""), "server")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_sslCA
          if firstHit
            Ops.set(
              param,
              "nsCertType",
              Ops.add(Ops.get_string(param, "nsCertType", ""), ",sslCA")
            )
          else
            Ops.set(
              param,
              "nsCertType",
              Ops.add(Ops.get_string(param, "nsCertType", ""), "sslCA")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_email
          if firstHit
            Ops.set(
              param,
              "nsCertType",
              Ops.add(Ops.get_string(param, "nsCertType", ""), ",email")
            )
          else
            Ops.set(
              param,
              "nsCertType",
              Ops.add(Ops.get_string(param, "nsCertType", ""), "email")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_reserved
          if firstHit
            Ops.set(
              param,
              "nsCertType",
              Ops.add(Ops.get_string(param, "nsCertType", ""), ",reserved")
            )
          else
            Ops.set(
              param,
              "nsCertType",
              Ops.add(Ops.get_string(param, "nsCertType", ""), "reserved")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_emailCA
          if firstHit
            Ops.set(
              param,
              "nsCertType",
              Ops.add(Ops.get_string(param, "nsCertType", ""), ",emailCA")
            )
          else
            Ops.set(
              param,
              "nsCertType",
              Ops.add(Ops.get_string(param, "nsCertType", ""), "emailCA")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_objsign
          if firstHit
            Ops.set(
              param,
              "nsCertType",
              Ops.add(Ops.get_string(param, "nsCertType", ""), ",objsign")
            )
          else
            Ops.set(
              param,
              "nsCertType",
              Ops.add(Ops.get_string(param, "nsCertType", ""), "objsign")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_objCA
          if firstHit
            Ops.set(
              param,
              "nsCertType",
              Ops.add(Ops.get_string(param, "nsCertType", ""), ",objCA")
            )
          else
            Ops.set(
              param,
              "nsCertType",
              Ops.add(Ops.get_string(param, "nsCertType", ""), "objCA")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_cri_nsCertType
          Ops.set(
            param,
            "nsCertType",
            Ops.add("critical,", Ops.get_string(param, "nsCertType", ""))
          )
        end
      end
      if CaMgm.adv_digitalSignature || CaMgm.adv_nonRepudiation ||
          CaMgm.adv_cRLSign ||
          CaMgm.adv_keyEncipherment ||
          CaMgm.adv_dataEncipherment ||
          CaMgm.adv_encipherOnly ||
          CaMgm.adv_keyAgreement ||
          CaMgm.adv_keyCertSign ||
          CaMgm.adv_decipherOnly
        firstHit = false
        if CaMgm.adv_nonRepudiation
          Ops.set(param, "keyUsage", "nonRepudiation")
          firstHit = true
        end
        if CaMgm.adv_digitalSignature
          if firstHit
            Ops.set(
              param,
              "keyUsage",
              Ops.add(
                Ops.get_string(param, "keyUsage", ""),
                ",digitalSignature"
              )
            )
          else
            Ops.set(
              param,
              "keyUsage",
              Ops.add(Ops.get_string(param, "keyUsage", ""), "digitalSignature")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_cRLSign
          if firstHit
            Ops.set(
              param,
              "keyUsage",
              Ops.add(Ops.get_string(param, "keyUsage", ""), ",cRLSign")
            )
          else
            Ops.set(
              param,
              "keyUsage",
              Ops.add(Ops.get_string(param, "keyUsage", ""), "cRLSign")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_keyEncipherment
          if firstHit
            Ops.set(
              param,
              "keyUsage",
              Ops.add(Ops.get_string(param, "keyUsage", ""), ",keyEncipherment")
            )
          else
            Ops.set(
              param,
              "keyUsage",
              Ops.add(Ops.get_string(param, "keyUsage", ""), "keyEncipherment")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_dataEncipherment
          if firstHit
            Ops.set(
              param,
              "keyUsage",
              Ops.add(
                Ops.get_string(param, "keyUsage", ""),
                ",dataEncipherment"
              )
            )
          else
            Ops.set(
              param,
              "keyUsage",
              Ops.add(Ops.get_string(param, "keyUsage", ""), "dataEncipherment")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_encipherOnly
          if firstHit
            Ops.set(
              param,
              "keyUsage",
              Ops.add(Ops.get_string(param, "keyUsage", ""), ",encipherOnly")
            )
          else
            Ops.set(
              param,
              "keyUsage",
              Ops.add(Ops.get_string(param, "keyUsage", ""), "encipherOnly")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_keyAgreement
          if firstHit
            Ops.set(
              param,
              "keyUsage",
              Ops.add(Ops.get_string(param, "keyUsage", ""), ",keyAgreement")
            )
          else
            Ops.set(
              param,
              "keyUsage",
              Ops.add(Ops.get_string(param, "keyUsage", ""), "keyAgreement")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_keyCertSign
          if firstHit
            Ops.set(
              param,
              "keyUsage",
              Ops.add(Ops.get_string(param, "keyUsage", ""), ",keyCertSign")
            )
          else
            Ops.set(
              param,
              "keyUsage",
              Ops.add(Ops.get_string(param, "keyUsage", ""), "keyCertSign")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_decipherOnly
          if firstHit
            Ops.set(
              param,
              "keyUsage",
              Ops.add(Ops.get_string(param, "keyUsage", ""), ",decipherOnly")
            )
          else
            Ops.set(
              param,
              "keyUsage",
              Ops.add(Ops.get_string(param, "keyUsage", ""), "decipherOnly")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_cri_key_usage
          Ops.set(
            param,
            "keyUsage",
            Ops.add("critical,", Ops.get_string(param, "keyUsage", ""))
          )
        end
      end
      if Ops.greater_than(Builtins.size(CaMgm.exp_subjectKeyIdentifier), 0)
        if CaMgm.exp_cri_subjectKeyIdentifier
          Ops.set(
            param,
            "subjectKeyIdentifier",
            Ops.add("critical,", CaMgm.exp_subjectKeyIdentifier)
          )
        else
          Ops.set(param, "subjectKeyIdentifier", CaMgm.exp_subjectKeyIdentifier)
        end
      end
      if Ops.greater_than(Builtins.size(CaMgm.adv_subject_alt_name_list), 0) ||
          Ops.greater_than(Builtins.size(CaMgm.emailList), 1) || # without default entry
          CaMgm.adv_copy_subject_alt_name &&
            Ops.greater_than(Builtins.size(CaMgm.emailList), 0)
        prevFound = false
        if CaMgm.adv_cri_subject_alt_name
          Ops.set(param, "subjectAltName", "critical")
          prevFound = true
        else
          Ops.set(param, "subjectAltName", "")
        end
        # taking EMAIL
        Builtins.foreach(CaMgm.emailList) do |element|
          if Ops.get_boolean(element, "default", false) == false
            Ops.set(
              param,
              "subjectAltName",
              Ops.add(
                Ops.add(
                  Ops.add(
                    Ops.get_string(param, "subjectAltName", ""),
                    prevFound ? "," : ""
                  ),
                  "email:"
                ),
                Ops.get_string(element, "name", "")
              )
            )
            prevFound = true
          end
        end
        Builtins.foreach(CaMgm.adv_subject_alt_name_list) do |element|
          Ops.set(
            param,
            "subjectAltName",
            Ops.add(
              Ops.add(
                Ops.add(
                  Ops.add(
                    Ops.get_string(param, "subjectAltName", ""),
                    prevFound ? "," : ""
                  ),
                  Ops.get_string(element, "kind", "")
                ),
                ":"
              ),
              Ops.get_string(element, "name", "")
            )
          )
          prevFound = true
        end
        if CaMgm.adv_copy_subject_alt_name
          Ops.set(
            param,
            "subjectAltName",
            Ops.add(
              Ops.add(
                Ops.get_string(param, "subjectAltName", ""),
                prevFound ? "," : ""
              ),
              "email:copy"
            )
          )
        end
      end
      if Ops.greater_than(Builtins.size(CaMgm.adv_nsSslServerName), 0)
        Ops.set(
          param,
          "nsSslServerName",
          Ops.add(
            CaMgm.adv_cri_nsSslServerName ? "critical," : "",
            CaMgm.adv_nsSslServerName
          )
        )
      end
      if Ops.greater_than(Builtins.size(CaMgm.exp_extendedKeyUsage), 0)
        Ops.set(
          param,
          "extendedKeyUsage",
          Ops.add(
            CaMgm.exp_cri_extendedKeyUsage ? "critical," : "",
            CaMgm.exp_extendedKeyUsage
          )
        )
      end
      if Ops.greater_than(Builtins.size(CaMgm.exp_authorityInfoAccess), 0)
        Ops.set(
          param,
          "authorityInfoAccess",
          Ops.add(
            CaMgm.exp_cri_authorityInfoAccess ? "critical," : "",
            CaMgm.exp_authorityInfoAccess
          )
        )
      end

      if kind == "Root CA"
        #	    y2milestone("CaManagement::AddRootCA(%1)", param);
        return YaPI::CaManagement.AddRootCA(param) == nil ? false : true
      end
      if kind == "Server Certificate" || kind == "Client Certificate"
        #	    y2milestone("CaManagement::AddCertificate(%1)", param);
        #param["notext"] = "1";
        filename = YaPI::CaManagement.AddCertificate(param)
        if filename == nil || Builtins.size(filename) == 0
          return false
        else
          Builtins.y2milestone("Certificate created in : %1", filename)
          return true
        end
      end
      if kind == "Sub CA"
        #	    y2milestone("CaManagement::AddSubCA(%1)", param);
        return YaPI::CaManagement.AddSubCA(param) == nil ? false : true
      end
      if kind == "signRequest"
        #param["notext"] = "1";
        #	    y2milestone("CaManagement::IssueCertificate(%1)", param);
        return YaPI::CaManagement.IssueCertificate(param) == nil ? false : true
      end
      if kind == "Server Request" || kind == "Client Request" ||
          kind == "Sub CA Request"
        #	    y2milestone("CaManagement::AddRequest(%1)", param);
        return YaPI::CaManagement.AddRequest(param) == nil ? false : true
      end

      nil
    end

    # Writing default settings
    # @return true ( success )
    def new_cert_write_default
      kindmap = {
        "Root CA"            => "ca",
        "Sub CA"             => "ca",
        "Server Certificate" => "server",
        "Client Certificate" => "client"
      }

      param = {}

      # fillup parameters depending on kind

      Ops.set(param, "caName", CaMgm.currentCA)
      # set the real password later.
      Ops.set(param, "caPasswd", "<was set>")
      Ops.set(
        param,
        "certType",
        Ops.get_string(kindmap, CaMgm.currentDefault, "")
      )

      if CaMgm.adv_ca != "none"
        if CaMgm.adv_cri_ca
          Ops.set(param, "basicConstraints", Ops.add("critical,", CaMgm.adv_ca))
        else
          Ops.set(param, "basicConstraints", CaMgm.adv_ca)
        end
      else
        Ops.set(param, "basicConstraints", "critical") if CaMgm.adv_cri_ca
      end

      if CaMgm.adv_pathlen
        Ops.set(
          param,
          "basicConstraints",
          Ops.add(
            Ops.add(Ops.get_string(param, "basicConstraints", ""), ", pathlen:"),
            Builtins.tostring(CaMgm.adv_pathlenValue)
          )
        )
      end

      if CaMgm.adv_cri_nsComment
        Ops.set(param, "nsComment", Ops.add("critical,", CaMgm.adv_nsComment))
      else
        Ops.set(param, "nsComment", CaMgm.adv_nsComment)
      end
      if CaMgm.adv_client || CaMgm.adv_server || CaMgm.adv_sslCA ||
          CaMgm.adv_email ||
          CaMgm.adv_reserved ||
          CaMgm.adv_emailCA ||
          CaMgm.adv_objsign ||
          CaMgm.adv_objCA
        firstHit = false
        if CaMgm.adv_client
          Ops.set(param, "nsCertType", "client")
          firstHit = true
        end
        if CaMgm.adv_server
          if firstHit
            Ops.set(
              param,
              "nsCertType",
              Ops.add(Ops.get_string(param, "nsCertType", ""), ",server")
            )
          else
            Ops.set(
              param,
              "nsCertType",
              Ops.add(Ops.get_string(param, "nsCertType", ""), "server")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_sslCA
          if firstHit
            Ops.set(
              param,
              "nsCertType",
              Ops.add(Ops.get_string(param, "nsCertType", ""), ",sslCA")
            )
          else
            Ops.set(
              param,
              "nsCertType",
              Ops.add(Ops.get_string(param, "nsCertType", ""), "sslCA")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_email
          if firstHit
            Ops.set(
              param,
              "nsCertType",
              Ops.add(Ops.get_string(param, "nsCertType", ""), ",email")
            )
          else
            Ops.set(
              param,
              "nsCertType",
              Ops.add(Ops.get_string(param, "nsCertType", ""), "email")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_reserved
          if firstHit
            Ops.set(
              param,
              "nsCertType",
              Ops.add(Ops.get_string(param, "nsCertType", ""), ",reserved")
            )
          else
            Ops.set(
              param,
              "nsCertType",
              Ops.add(Ops.get_string(param, "nsCertType", ""), "reserved")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_emailCA
          if firstHit
            Ops.set(
              param,
              "nsCertType",
              Ops.add(Ops.get_string(param, "nsCertType", ""), ",emailCA")
            )
          else
            Ops.set(
              param,
              "nsCertType",
              Ops.add(Ops.get_string(param, "nsCertType", ""), "emailCA")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_objsign
          if firstHit
            Ops.set(
              param,
              "nsCertType",
              Ops.add(Ops.get_string(param, "nsCertType", ""), ",objsign")
            )
          else
            Ops.set(
              param,
              "nsCertType",
              Ops.add(Ops.get_string(param, "nsCertType", ""), "objsign")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_objCA
          if firstHit
            Ops.set(
              param,
              "nsCertType",
              Ops.add(Ops.get_string(param, "nsCertType", ""), ",objCA")
            )
          else
            Ops.set(
              param,
              "nsCertType",
              Ops.add(Ops.get_string(param, "nsCertType", ""), "objCA")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_cri_nsCertType
          Ops.set(
            param,
            "nsCertType",
            Ops.add("critical,", Ops.get_string(param, "nsCertType", ""))
          )
        end
      end
      if CaMgm.adv_digitalSignature || CaMgm.adv_nonRepudiation ||
          CaMgm.adv_cRLSign ||
          CaMgm.adv_keyEncipherment ||
          CaMgm.adv_dataEncipherment ||
          CaMgm.adv_encipherOnly ||
          CaMgm.adv_keyAgreement ||
          CaMgm.adv_keyCertSign ||
          CaMgm.adv_decipherOnly
        firstHit = false
        if CaMgm.adv_nonRepudiation
          Ops.set(param, "keyUsage", "nonRepudiation")
          firstHit = true
        end
        if CaMgm.adv_digitalSignature
          if firstHit
            Ops.set(
              param,
              "keyUsage",
              Ops.add(
                Ops.get_string(param, "keyUsage", ""),
                ",digitalSignature"
              )
            )
          else
            Ops.set(
              param,
              "keyUsage",
              Ops.add(Ops.get_string(param, "keyUsage", ""), "digitalSignature")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_cRLSign
          if firstHit
            Ops.set(
              param,
              "keyUsage",
              Ops.add(Ops.get_string(param, "keyUsage", ""), ",cRLSign")
            )
          else
            Ops.set(
              param,
              "keyUsage",
              Ops.add(Ops.get_string(param, "keyUsage", ""), "cRLSign")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_keyEncipherment
          if firstHit
            Ops.set(
              param,
              "keyUsage",
              Ops.add(Ops.get_string(param, "keyUsage", ""), ",keyEncipherment")
            )
          else
            Ops.set(
              param,
              "keyUsage",
              Ops.add(Ops.get_string(param, "keyUsage", ""), "keyEncipherment")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_dataEncipherment
          if firstHit
            Ops.set(
              param,
              "keyUsage",
              Ops.add(
                Ops.get_string(param, "keyUsage", ""),
                ",dataEncipherment"
              )
            )
          else
            Ops.set(
              param,
              "keyUsage",
              Ops.add(Ops.get_string(param, "keyUsage", ""), "dataEncipherment")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_encipherOnly
          if firstHit
            Ops.set(
              param,
              "keyUsage",
              Ops.add(Ops.get_string(param, "keyUsage", ""), ",encipherOnly")
            )
          else
            Ops.set(
              param,
              "keyUsage",
              Ops.add(Ops.get_string(param, "keyUsage", ""), "encipherOnly")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_keyAgreement
          if firstHit
            Ops.set(
              param,
              "keyUsage",
              Ops.add(Ops.get_string(param, "keyUsage", ""), ",keyAgreement")
            )
          else
            Ops.set(
              param,
              "keyUsage",
              Ops.add(Ops.get_string(param, "keyUsage", ""), "keyAgreement")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_keyCertSign
          if firstHit
            Ops.set(
              param,
              "keyUsage",
              Ops.add(Ops.get_string(param, "keyUsage", ""), ",keyCertSign")
            )
          else
            Ops.set(
              param,
              "keyUsage",
              Ops.add(Ops.get_string(param, "keyUsage", ""), "keyCertSign")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_decipherOnly
          if firstHit
            Ops.set(
              param,
              "keyUsage",
              Ops.add(Ops.get_string(param, "keyUsage", ""), ",decipherOnly")
            )
          else
            Ops.set(
              param,
              "keyUsage",
              Ops.add(Ops.get_string(param, "keyUsage", ""), "decipherOnly")
            )
            firstHit = true
          end
        end
        if CaMgm.adv_cri_key_usage
          Ops.set(
            param,
            "keyUsage",
            Ops.add("critical,", Ops.get_string(param, "keyUsage", ""))
          )
        end
      end
      if Ops.greater_than(Builtins.size(CaMgm.exp_subjectKeyIdentifier), 0)
        if CaMgm.exp_cri_subjectKeyIdentifier
          Ops.set(
            param,
            "subjectKeyIdentifier",
            Ops.add("critical,", CaMgm.exp_subjectKeyIdentifier)
          )
        else
          Ops.set(param, "subjectKeyIdentifier", CaMgm.exp_subjectKeyIdentifier)
        end
      end
      if Ops.greater_than(Builtins.size(CaMgm.exp_authorityKeyIdentifier), 0)
        if CaMgm.exp_cri_authorityKeyIdentifier
          Ops.set(
            param,
            "authorityKeyIdentifier",
            Ops.add("critical,", CaMgm.exp_authorityKeyIdentifier)
          )
        else
          Ops.set(
            param,
            "authorityKeyIdentifier",
            CaMgm.exp_authorityKeyIdentifier
          )
        end
      end
      if Ops.greater_than(Builtins.size(CaMgm.adv_subject_alt_name_list), 0) ||
          Ops.greater_than(Builtins.size(CaMgm.emailList), 1) || # without default entry
          CaMgm.adv_copy_subject_alt_name
        prevFound = false
        if CaMgm.adv_cri_subject_alt_name
          Ops.set(param, "subjectAltName", "critical")
          prevFound = true
        else
          Ops.set(param, "subjectAltName", "")
        end
        # taking EMAIL
        Builtins.foreach(CaMgm.emailList) do |element|
          if Ops.get_boolean(element, "default", false) == false
            Ops.set(
              param,
              "subjectAltName",
              Ops.add(
                Ops.add(
                  Ops.add(
                    Ops.get_string(param, "subjectAltName", ""),
                    prevFound ? "," : ""
                  ),
                  "email:"
                ),
                Ops.get_string(element, "name", "")
              )
            )
            prevFound = true
          end
        end
        Builtins.foreach(CaMgm.adv_subject_alt_name_list) do |element|
          Ops.set(
            param,
            "subjectAltName",
            Ops.add(
              Ops.add(
                Ops.add(
                  Ops.add(
                    Ops.get_string(param, "subjectAltName", ""),
                    prevFound ? "," : ""
                  ),
                  Ops.get_string(element, "kind", "")
                ),
                ":"
              ),
              Ops.get_string(element, "name", "")
            )
          )
          prevFound = true
        end
        if CaMgm.adv_copy_subject_alt_name
          Ops.set(
            param,
            "subjectAltName",
            Ops.add(
              Ops.add(
                Ops.get_string(param, "subjectAltName", ""),
                prevFound ? "," : ""
              ),
              "email:copy"
            )
          )
        end
      end
      if Ops.greater_than(Builtins.size(CaMgm.adv_issuer_alt_name_list), 0) ||
          CaMgm.adv_copy_issuer_alt_name
        prevFound = false
        if CaMgm.adv_cri_issuer_alt_name
          Ops.set(param, "issuerAltName", "critical")
          prevFound = true
        else
          Ops.set(param, "issuerAltName", "")
        end
        Builtins.foreach(CaMgm.adv_issuer_alt_name_list) do |element|
          Ops.set(
            param,
            "issuerAltName",
            Ops.add(
              Ops.add(
                Ops.add(
                  Ops.add(
                    Ops.get_string(param, "issuerAltName", ""),
                    prevFound ? "," : ""
                  ),
                  Ops.get_string(element, "kind", "")
                ),
                ":"
              ),
              Ops.get_string(element, "name", "")
            )
          )
          prevFound = true
        end
        if CaMgm.adv_copy_issuer_alt_name
          Ops.set(
            param,
            "issuerAltName",
            Ops.add(
              Ops.add(
                Ops.get_string(param, "issuerAltName", ""),
                prevFound ? "," : ""
              ),
              "issuer:copy"
            )
          )
        end
      end
      if Ops.greater_than(Builtins.size(CaMgm.exp_netscape_nsBaseUrl), 0)
        Ops.set(
          param,
          "nsBaseUrl",
          Ops.add(
            CaMgm.exp_cri_netscape_nsBaseUrl ? "critical," : "",
            CaMgm.exp_netscape_nsBaseUrl
          )
        )
      end
      if Ops.greater_than(Builtins.size(CaMgm.exp_netscape_nsRevocationUrl), 0)
        Ops.set(
          param,
          "nsRevocationUrl",
          Ops.add(
            CaMgm.exp_cri_netscape_nsRevocationUrl ? "critical," : "",
            CaMgm.exp_netscape_nsRevocationUrl
          )
        )
      end
      if Ops.greater_than(
          Builtins.size(CaMgm.exp_netscape_nsCaRevocationUrl),
          0
        )
        Ops.set(
          param,
          "nsCaRevocationUrl",
          Ops.add(
            CaMgm.exp_cri_netscape_nsCaRevocationUrl ? "critical," : "",
            CaMgm.exp_netscape_nsCaRevocationUrl
          )
        )
      end
      if Ops.greater_than(Builtins.size(CaMgm.exp_netscape_nsRenewalUrl), 0)
        Ops.set(
          param,
          "nsRenewalUrl",
          Ops.add(
            CaMgm.exp_cri_netscape_nsRenewalUrl ? "critical," : "",
            CaMgm.exp_netscape_nsRenewalUrl
          )
        )
      end
      if Ops.greater_than(Builtins.size(CaMgm.exp_netscape_nsCaPolicyUrl), 0)
        Ops.set(
          param,
          "nsCaPolicyUrl",
          Ops.add(
            CaMgm.exp_cri_netscape_nsCaPolicyUrl ? "critical," : "",
            CaMgm.exp_netscape_nsCaPolicyUrl
          )
        )
      end
      if Ops.greater_than(Builtins.size(CaMgm.adv_nsSslServerName), 0)
        Ops.set(
          param,
          "nsSslServerName",
          Ops.add(
            CaMgm.adv_cri_nsSslServerName ? "critical," : "",
            CaMgm.adv_nsSslServerName
          )
        )
      end
      if Ops.greater_than(Builtins.size(CaMgm.exp_extendedKeyUsage), 0)
        Ops.set(
          param,
          "extendedKeyUsage",
          Ops.add(
            CaMgm.exp_cri_extendedKeyUsage ? "critical," : "",
            CaMgm.exp_extendedKeyUsage
          )
        )
      end
      if Ops.greater_than(Builtins.size(CaMgm.exp_authorityInfoAccess), 0)
        Ops.set(
          param,
          "authorityInfoAccess",
          Ops.add(
            CaMgm.exp_cri_authorityInfoAccess ? "critical," : "",
            CaMgm.exp_authorityInfoAccess
          )
        )
      end
      if Ops.greater_than(Builtins.size(CaMgm.adv_distribution_point), 0)
        Ops.set(
          param,
          "crlDistributionPoints",
          Ops.add(
            CaMgm.adv_cri_distribution_point ? "critical," : "",
            CaMgm.adv_distribution_point
          )
        )
      end

      Builtins.y2milestone("CaManagement::WriteCertificateDefaults(%1)", param)

      # now set the password
      Ops.set(param, "caPasswd", getPassword(CaMgm.currentCA))

      YaPI::CaManagement.WriteCertificateDefaults(param)
    end


    # Creating default CA/Certificate
    # @return [Boolean] ( success )
    def create_default_CA_certificate
      UI.BusyCursor
      UI.OpenDialog(VBox(Label(_("Creating certificate..."))))

      # creating CA
      new_cert_init("Root CA")
      if Ops.greater_than(Builtins.size(CaMgm.prop_email), 0)
        CaMgm.emailList = [{ "default" => true, "name" => CaMgm.prop_email }]
      end
      CaMgm.commonName = CaMgm.prop_ca_commonName
      CaMgm.CAName = CaMgm.prop_CAName
      CaMgm.organisation = CaMgm.prop_organisation
      CaMgm.organisationUnit = CaMgm.prop_organisationUnit
      CaMgm.locality = CaMgm.prop_locality
      CaMgm.state = CaMgm.prop_state
      CaMgm.country = CaMgm.prop_country
      CaMgm.password = CaMgm.prop_password

      Builtins.y2milestone("Creating default Root CA")
      if cert_write("Root CA")
        # saving password for the generated CA
        Ops.set(CaMgm.passwdMap, CaMgm.prop_CAName, CaMgm.prop_password)
        CaMgm.currentCA = CaMgm.prop_CAName

        # Creating server certificate
        new_cert_init("Server Certificate")
        if Ops.greater_than(Builtins.size(CaMgm.prop_email), 0)
          CaMgm.emailList = [{ "default" => true, "name" => CaMgm.prop_email }]
        end
        CaMgm.commonName = CaMgm.prop_server_commonName
        CaMgm.CAName = CaMgm.prop_CAName
        CaMgm.organisation = CaMgm.prop_organisation
        CaMgm.organisationUnit = CaMgm.prop_organisationUnit
        CaMgm.locality = CaMgm.prop_locality
        CaMgm.state = CaMgm.prop_state
        CaMgm.country = CaMgm.prop_country
        CaMgm.password = CaMgm.prop_password

        Builtins.y2milestone("Creating default Server Certificate")

        if !cert_write("Server Certificate")
          UI.CloseDialog
          showErrorCaManagement
          Popup.Message(
            _(
              "The default certificate can also be created in\nthe CA Management module.\n"
            )
          )
          return false
        else
          certList = Convert.convert(
            YaPI::CaManagement.ReadCertificateList(
              {
                "caName"   => CaMgm.prop_CAName,
                "caPasswd" => CaMgm.prop_password
              }
            ),
            :from => "list",
            :to   => "list <map>"
          )
          Builtins.y2milestone(
            "ReadCertificateList(%1): %2",
            CaMgm.prop_CAName,
            certList
          )

          # Exporting to common server certificate
          tmpdir = Convert.to_string(SCR.Read(path(".target.tmpdir")))
          yapiret = Convert.to_string(
            YaPI::CaManagement.ExportCertificate(
              {
                "caName"          => CaMgm.prop_CAName,
                "caPasswd"        => CaMgm.prop_password,
                "certificate"     => Ops.get_string(
                  Ops.get(certList, 0, {}),
                  "certificate",
                  ""
                ),
                "keyPasswd"       => CaMgm.prop_password,
                "exportFormat"    => "PKCS12_CHAIN",
                "destinationFile" => Ops.add(tmpdir, "/YaST-Servercert.p12"),
                "P12Password"     => CaMgm.prop_password
              }
            )
          )
          Builtins.y2milestone(
            "ExportCertificate(%1) return %2",
            {
              "caName"          => CaMgm.prop_CAName,
              "certificate"     => Ops.get_string(
                Ops.get(certList, 0, {}),
                "certificate",
                ""
              ),
              "exportFormat"    => "PKCS12_CHAIN",
              "destinationFile" => Ops.add(tmpdir, "/YaST-Servercert.p12")
            },
            yapiret
          )
          if yapiret == nil || yapiret != "1"
            UI.CloseDialog
            showErrorCaManagement
            return false
          end

          importret = YaPI::CaManagement.ImportCommonServerCertificate(
            {
              "passwd" => CaMgm.prop_password,
              "inFile" => Ops.add(tmpdir, "/YaST-Servercert.p12")
            }
          )
          Builtins.y2milestone(
            "ImportCommonServerCertificate() return %1",
            importret
          )
          if importret == nil || !importret
            UI.CloseDialog
            showErrorCaManagement
            return false
          end
        end
      else
        UI.CloseDialog
        showErrorCaManagement
        Popup.Message(
          _(
            "The default certificate can also be created in\nthe CA Management module.\n"
          )
        )
        return false
      end

      UI.CloseDialog

      true
    end
  end
end
