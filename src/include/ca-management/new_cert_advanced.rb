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
#   new_cert_advanced.ycp
#
# Module:
#   CA Management
#
# Summary:
#   Creating a new CA/Certificate ( Advanced Settings )
#
# Authors:
#   Stefan Schubert <schubi@suse.de>
#
# $Id$
#
# Creating a new CA/Certificate
#
module Yast
  module CaManagementNewCertAdvancedInclude
    def initialize_ca_management_new_cert_advanced(include_target)
      Yast.import "UI"

      textdomain "ca-management"

      Yast.import "CaMgm"
      Yast.import "Wizard"
      Yast.import "Label"
      Yast.import "Popup"
      Yast.import "YaPI::CaManagement"

      Yast.include include_target, "ca-management/util.rb"
      Yast.include include_target, "ca-management/new_cert_items.rb"

      @lastItem = nil
    end

    # Creating new CA/Certificate ( Advanced Settings )
    # @param [Boolean] nextbutton - The dialog has a next button
    # @return `next, 'back, 'cancel, 'again
    def new_cert_advanced(nextbutton, kind)
      itemList = []

      if kind == "Client Request" || kind == "Server Request"
        itemList = deep_copy(@requestItemList)
      else
        itemList = deep_copy(@generalItemList)
      end

      button = HBox(
        PushButton(Id(:help), Opt(:key_F1), Label.HelpButton),
        HStretch(),
        PushButton(Id(:abort), Opt(:key_F9), Label.AbortButton),
        HStretch(),
        PushButton(Id(:back), Opt(:key_F8), Label.OKButton),
        Empty()
      )

      if nextbutton
        # The dialog has a next button
        button = HBox(
          PushButton(Id(:back), Opt(:key_F8), Label.BackButton),
          HStretch(),
          PushButton(Id(:abort), Opt(:key_F9), Label.AbortButton),
          HStretch(),
          PushButton(Id(:next), Opt(:key_F10), Label.NextButton),
          Empty()
        )
      end

      UI.OpenDialog(
        Opt(:defaultsize),
        VBox(
          VSpacing(3),
          HSpacing(85),
          HWeight(
            70,
            VBox(
              HBox(
                HWeight(
                  35,
                  # tree widget label
                  Tree(
                    Id(:tree),
                    Opt(:notify, :vstretch),
                    _("&Advanced Options"),
                    itemList
                  )
                ),
                HSpacing(1),
                HWeight(
                  65,
                  VBox(
                    HSpacing(60),
                    # label widget
                    Left(
                      Heading(
                        Id(:heading),
                        Opt(:hstretch),
                        _("Current Selection: ")
                      )
                    ),
                    VSpacing(0.5),
                    VBox(
                      HBox(
                        HStretch(),
                        PushButton(Id(:default), Opt(:disabled), _("&Default"))
                      ),
                      ReplacePoint(
                        Id(:replace),
                        RichText(Id(:id_advanced), @advanced_help)
                      ),
                      VStretch()
                    )
                  )
                )
              ),
              button
            )
          )
        )
      )

      UI.ChangeWidget(Id(:tree), :CurrentItem, :advanced)
      @lastItem = :advanced

      ret = :dummy

      while ret != :back && ret != :abort && ret != :next
        ret = Convert.to_symbol(UI.UserInput)

        ret = :abort if ret == :cancel

        # "Default" button
        if ret == :default
          item = Ops.get_map(@itemMap, @lastItem, {})
          function = Ops.get(item, "default")
          ret2 = Builtins.eval(function) if function != nil
          function = Ops.get(item, "getCallback")
          ret2 = Builtins.eval(function) if function != nil
        else
          selected = Convert.to_symbol(UI.QueryWidget(Id(:tree), :CurrentItem))
          Builtins.y2milestone("Selected: %1", selected)

          # saving settings for old selection
          item = Ops.get_map(@itemMap, @lastItem, {})
          function = Ops.get(item, "setCallback")
          error = ""
          if function != nil
            ret2 = Builtins.eval(function)
            error = Convert.to_string(ret2) if Ops.is_string?(ret2)
          end

          if Ops.greater_than(Builtins.size(error), 0)
            Popup.Error(error)
            # set selection back
            UI.ChangeWidget(Id(:tree), :CurrentItem, @lastItem)
          else
            if ret == :help
              UI.OpenDialog(
                Opt(:decorated),
                HBox(
                  VSpacing(16),
                  VBox(
                    HSpacing(60),
                    # popup window header
                    Heading(_("Help")),
                    VSpacing(0.5),
                    RichText(@advanced_help),
                    VSpacing(1.5),
                    # push button label
                    PushButton(Id(:ok), Opt(:default, :key_F10), Label.OKButton)
                  )
                )
              )

              UI.SetFocus(Id(:ok))
              UI.UserInput
              UI.CloseDialog
            elsif ret == :add
              selected2 = Convert.to_symbol(
                UI.QueryWidget(Id(:tree), :CurrentItem)
              )
              Builtins.y2milestone("Add for: %1", selected2)

              # Calling Add callback
              item2 = Ops.get_map(@itemMap, @lastItem, {})
              function2 = Ops.get(item2, "addCallback")
              ret2 = Builtins.eval(function2) if function2 != nil
            elsif ret == :modify
              selected2 = Convert.to_symbol(
                UI.QueryWidget(Id(:tree), :CurrentItem)
              )
              Builtins.y2milestone("Modify for: %1", selected2)

              # Calling Modify callback
              item2 = Ops.get_map(@itemMap, @lastItem, {})
              function2 = Ops.get(item2, "modifyCallback")
              ret2 = Builtins.eval(function2) if function2 != nil
            elsif ret == :delete
              selected2 = Convert.to_symbol(
                UI.QueryWidget(Id(:tree), :CurrentItem)
              )
              Builtins.y2milestone("Delete for: %1", selected2)

              # Calling Delete callback
              item2 = Ops.get_map(@itemMap, @lastItem, {})
              function2 = Ops.get(item2, "deleteCallback")
              ret2 = Builtins.eval(function2) if function2 != nil
            else
              # no error --> goto next selection
              @lastItem = selected
              item = Ops.get_map(@itemMap, selected, {})
              # header label
              UI.ChangeWidget(
                Id(:heading),
                :Value,
                Ops.add(
                  _("Current Selection: "),
                  Ops.get_string(item, "name", "")
                )
              )
              # showing concerning input fields
              UI.ReplaceWidget(
                Id(:replace),
                Ops.get_term(item, "widget", Empty())
              )
              # enable/disable Default button
              function2 = Ops.get(item, "default")
              if function2 != nil
                UI.ChangeWidget(Id(:default), :Enabled, true)
              else
                UI.ChangeWidget(Id(:default), :Enabled, false)
              end

              # getting values
              function2 = Ops.get(item, "getCallback")
              ret2 = Builtins.eval(function2) if function2 != nil
            end
          end
        end
      end

      UI.CloseDialog

      ret
    end
  end
end
