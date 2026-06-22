use crate::template::{Endian, Field, FieldType, ProtocolTemplate};
use cursive::traits::*;
use cursive::views::{
    Button, Dialog, DummyView, EditView, LinearLayout, ListView, SelectView, TextView,
};
use cursive::Cursive;
use std::rc::Rc;

pub struct TemplateEditor {
    template: ProtocolTemplate,
}

impl TemplateEditor {
    pub fn new(template: ProtocolTemplate) -> Self {
        TemplateEditor { template }
    }

    pub fn run(&mut self) -> Option<ProtocolTemplate> {
        let mut siv = cursive::default();
        siv.set_user_data(self.template.clone());

        build_main_view(&mut siv);

        siv.add_global_callback('q', |s| s.quit());
        siv.add_global_callback(cursive::event::Key::Esc, |s| {
            s.set_user_data::<ProtocolTemplate>(ProtocolTemplate {
                name: None,
                endian: Endian::Big,
                signature: None,
                fields: vec![],
            });
            s.quit();
        });

        siv.run();

        let result = siv.take_user_data::<ProtocolTemplate>().unwrap();
        if result.fields.is_empty() && result.signature.is_none() && result.name.is_none() {
            None
        } else {
            Some(result)
        }
    }
}

fn build_main_view(siv: &mut Cursive) {
    let template = siv.user_data::<ProtocolTemplate>().unwrap().clone();

    let title = template
        .name
        .clone()
        .unwrap_or_else(|| "未命名模板".to_string());

    let mut list_view = ListView::new();

    let name_edit = EditView::new()
        .content(title.clone())
        .on_submit(|s, name| {
            s.with_user_data(|t: &mut ProtocolTemplate| {
                t.name = if name.is_empty() {
                    None
                } else {
                    Some(name.to_string())
                };
            });
        })
        .fixed_width(30);
    list_view.add_child("名称", name_edit);

    let endian_str = match template.endian {
        Endian::Big => "大端 (Big Endian)",
        Endian::Little => "小端 (Little Endian)",
    };
    list_view.add_child(
        "字节序",
        Button::new(endian_str, |s| {
            s.with_user_data(|t: &mut ProtocolTemplate| {
                t.endian = match t.endian {
                    Endian::Big => Endian::Little,
                    Endian::Little => Endian::Big,
                };
            });
            rebuild_main_view(s);
        })
        .fixed_width(25),
    );

    let sig_info = match &template.signature {
        Some(sig) => format!("offset={}, bytes={}", sig.offset, sig.bytes),
        None => "未设置".to_string(),
    };
    list_view.add_child(
        "签名",
        LinearLayout::horizontal()
            .child(TextView::new(sig_info).fixed_width(30))
            .child(Button::new("清除", |s| {
                s.with_user_data(|t: &mut ProtocolTemplate| {
                    t.signature = None;
                });
                rebuild_main_view(s);
            })),
    );

    let mut field_select = SelectView::<usize>::new();
    for (i, field) in template.fields.iter().enumerate() {
        let label = format_field_label(i, field);
        field_select.add_item(label, i);
    }
    field_select.set_on_submit(|s, idx| {
        let idx = *idx;
        edit_field_dialog(s, idx);
    });

    let field_panel = Dialog::around(field_select.with_name("field_list").scrollable())
        .title("字段列表 (Enter编辑)")
        .min_height(15);

    let buttons = LinearLayout::horizontal()
        .child(Button::new("上移", |s| {
            move_selected_field(s, -1);
            rebuild_main_view(s);
        }))
        .child(DummyView.fixed_width(1))
        .child(Button::new("下移", |s| {
            move_selected_field(s, 1);
            rebuild_main_view(s);
        }))
        .child(DummyView.fixed_width(1))
        .child(Button::new("添加", |s| {
            add_field_dialog(s);
        }))
        .child(DummyView.fixed_width(1))
        .child(Button::new("删除", |s| {
            delete_selected_field(s);
            rebuild_main_view(s);
        }))
        .child(DummyView.fixed_width(3))
        .child(Button::new("确认 (S)", |s| {
            s.quit();
        }))
        .child(DummyView.fixed_width(1))
        .child(Button::new("取消 (Esc)", |s| {
            s.set_user_data::<ProtocolTemplate>(ProtocolTemplate {
                name: None,
                endian: Endian::Big,
                signature: None,
                fields: vec![],
            });
            s.quit();
        }));

    let main_layout = LinearLayout::vertical()
        .child(list_view)
        .child(DummyView.fixed_height(1))
        .child(field_panel)
        .child(DummyView.fixed_height(1))
        .child(buttons);

    siv.add_layer(
        cursive::views::OnEventView::new(
            Dialog::around(main_layout)
                .title("模板编辑 (↑↓选择, Enter编辑, S确认, Esc取消)"),
        )
        .on_event('s', |s| {
            s.quit();
        }),
    );
}

fn rebuild_main_view(siv: &mut Cursive) {
    siv.pop_layer();
    build_main_view(siv);
}

fn format_field_label(idx: usize, field: &Field) -> String {
    match field {
        Field::Scalar {
            name,
            data_type,
            length,
            ..
        } => {
            let type_str = field_type_to_str(data_type);
            let len_str = match length {
                Some(n) => format!(" [{}]", n),
                None => "".to_string(),
            };
            format!("[{}] {:<20} {}{}", idx, name, type_str, len_str)
        }
        Field::Struct { name, fields, .. } => {
            format!(
                "[{}] {:<20} struct ({}字段)",
                idx,
                name.as_deref().unwrap_or("(匿名)"),
                fields.len()
            )
        }
        Field::Conditional { name, .. } => {
            format!(
                "[{}] {:<20} conditional",
                idx,
                name.as_deref().unwrap_or("(匿名)")
            )
        }
        Field::Array { name, element, .. } => {
            let elem_type = match element.as_ref() {
                Field::Scalar { data_type, .. } => field_type_to_str(data_type).to_string(),
                _ => "struct".to_string(),
            };
            format!("[{}] {:<20} {}[]", idx, name, elem_type)
        }
    }
}

fn field_type_to_str(ft: &FieldType) -> &'static str {
    match ft {
        FieldType::U8 => "u8",
        FieldType::U16 => "u16",
        FieldType::U32 => "u32",
        FieldType::U64 => "u64",
        FieldType::I8 => "i8",
        FieldType::I16 => "i16",
        FieldType::I32 => "i32",
        FieldType::I64 => "i64",
        FieldType::F32 => "f32",
        FieldType::F64 => "f64",
        FieldType::Bytes => "bytes",
        FieldType::String => "string",
    }
}

fn move_selected_field(siv: &mut Cursive, delta: i32) {
    let selected = siv
        .call_on_name("field_list", |sv: &mut SelectView<usize>| {
            sv.selected_id().unwrap_or(0)
        })
        .unwrap_or(0);

    let mut template = siv.take_user_data::<ProtocolTemplate>().unwrap();
    let len = template.fields.len();
    if len < 2 {
        siv.set_user_data(template);
        return;
    }

    let new_idx = (selected as i32 + delta).max(0).min(len as i32 - 1) as usize;
    if new_idx != selected {
        template.fields.swap(selected, new_idx);
    }
    siv.set_user_data(template);
}

fn delete_selected_field(siv: &mut Cursive) {
    let selected = siv
        .call_on_name("field_list", |sv: &mut SelectView<usize>| {
            sv.selected_id().unwrap_or(0)
        })
        .unwrap_or(0);

    let mut template = siv.take_user_data::<ProtocolTemplate>().unwrap();
    if !template.fields.is_empty() && selected < template.fields.len() {
        template.fields.remove(selected);
    }
    siv.set_user_data(template);
}

fn add_field_dialog(siv: &mut Cursive) {
    let mut type_idx = 0usize;
    let mut types = SelectView::<FieldType>::new();
    let all_types: Vec<(FieldType, &str)> = vec![
        (FieldType::U8, "u8"),
        (FieldType::U16, "u16"),
        (FieldType::U32, "u32"),
        (FieldType::U64, "u64"),
        (FieldType::I8, "i8"),
        (FieldType::I16, "i16"),
        (FieldType::I32, "i32"),
        (FieldType::I64, "i64"),
        (FieldType::Bytes, "bytes"),
        (FieldType::String, "string"),
    ];
    for (i, (ft, label)) in all_types.iter().enumerate() {
        types.add_item(*label, ft.clone());
        if *ft == FieldType::U8 {
            type_idx = i;
        }
    }
    types.set_selection(type_idx);

    let name_edit = EditView::new()
        .content("new_field")
        .with_name("new_field_name")
        .fixed_width(20);

    let dialog = Dialog::around(
        LinearLayout::vertical()
            .child(TextView::new("字段名:"))
            .child(name_edit)
            .child(DummyView.fixed_height(1))
            .child(TextView::new("类型:"))
            .child(types.with_name("new_field_type").scrollable()),
    )
    .title("添加字段")
    .button("确认", move |s| {
        let name = s
            .call_on_name("new_field_name", |e: &mut EditView| e.get_content().to_string())
            .unwrap_or_else(|| "field".to_string());
        let ftype_opt = s
            .call_on_name("new_field_type", |sv: &mut SelectView<FieldType>| {
                sv.selection().as_ref().map(|rc: &Rc<FieldType>| (**rc).clone())
            })
            .flatten();
        let ftype = ftype_opt.unwrap_or(FieldType::U8);

        s.with_user_data(|t: &mut ProtocolTemplate| {
            let field = Field::Scalar {
                name: name.clone(),
                data_type: ftype,
                endian: None,
                length: None,
                length_field: None,
                encoding: None,
            };
            t.fields.push(field);
        });
        s.pop_layer();
        rebuild_main_view(s);
    })
    .button("取消", |s| {
        s.pop_layer();
    });

    siv.add_layer(dialog);
}

fn edit_field_dialog(siv: &mut Cursive, idx: usize) {
    let template = siv.user_data::<ProtocolTemplate>().unwrap().clone();
    let field = &template.fields[idx];

    match field {
        Field::Scalar {
            name,
            data_type,
            length,
            endian,
            length_field,
            encoding: _,
        } => {
            let name_edit = EditView::new()
                .content(name.clone())
                .with_name("edit_name")
                .fixed_width(25);

            let mut type_select = SelectView::<FieldType>::new();
            let all_types: Vec<(FieldType, &str)> = vec![
                (FieldType::U8, "u8"),
                (FieldType::U16, "u16"),
                (FieldType::U32, "u32"),
                (FieldType::U64, "u64"),
                (FieldType::I8, "i8"),
                (FieldType::I16, "i16"),
                (FieldType::I32, "i32"),
                (FieldType::I64, "i64"),
                (FieldType::Bytes, "bytes"),
                (FieldType::String, "string"),
            ];
            let mut sel_idx = 0;
            for (i, (ft, label)) in all_types.iter().enumerate() {
                type_select.add_item(*label, ft.clone());
                if ft == data_type {
                    sel_idx = i;
                }
            }
            type_select.set_selection(sel_idx);

            let len_str = length.map(|n| n.to_string()).unwrap_or_default();
            let len_edit = EditView::new()
                .content(len_str)
                .with_name("edit_length")
                .fixed_width(15);

            let len_field_str = length_field.clone().unwrap_or_default();
            let len_field_edit = EditView::new()
                .content(len_field_str)
                .with_name("edit_length_field")
                .fixed_width(20);

            let endian_label = match endian {
                Some(Endian::Big) => "大端",
                Some(Endian::Little) => "小端",
                None => "(默认)",
            };

            let layout = LinearLayout::vertical()
                .child(TextView::new("字段名:"))
                .child(name_edit)
                .child(DummyView.fixed_height(1))
                .child(TextView::new("数据类型:"))
                .child(type_select.with_name("edit_type"))
                .child(DummyView.fixed_height(1))
                .child(
                    LinearLayout::horizontal()
                        .child(TextView::new("长度(固定): ").fixed_width(12))
                        .child(len_edit),
                )
                .child(
                    LinearLayout::horizontal()
                        .child(TextView::new("长度字段名: ").fixed_width(12))
                        .child(len_field_edit),
                )
                .child(
                    LinearLayout::horizontal()
                        .child(TextView::new("字节序: ").fixed_width(12))
                        .child(TextView::new(endian_label).fixed_width(10)),
                );

            let dialog = Dialog::around(layout)
                .title(format!("编辑字段 [{}]", idx))
                .button("保存", move |s| {
                    let new_name = s
                        .call_on_name("edit_name", |e: &mut EditView| {
                            e.get_content().to_string()
                        })
                        .unwrap_or_default();
                    let new_type = s
                        .call_on_name("edit_type", |sv: &mut SelectView<FieldType>| {
                            sv.selection()
                                .as_ref()
                                .map(|rc: &Rc<FieldType>| (**rc).clone())
                        })
                        .flatten()
                        .unwrap_or(FieldType::U8);
                    let new_len = s
                        .call_on_name("edit_length", |e: &mut EditView| {
                            e.get_content().to_string()
                        })
                        .and_then(|s| s.parse::<usize>().ok());
                    let new_len_field = s
                        .call_on_name("edit_length_field", |e: &mut EditView| {
                            e.get_content().to_string()
                        })
                        .map(|s| if s.is_empty() { None } else { Some(s) })
                        .unwrap_or(None);

                    s.with_user_data(|t: &mut ProtocolTemplate| {
                        if idx < t.fields.len() {
                            let f = &mut t.fields[idx];
                            if let Field::Scalar {
                                name,
                                data_type,
                                length,
                                length_field,
                                ..
                            } = f
                            {
                                *name = new_name.clone();
                                *data_type = new_type;
                                *length = new_len;
                                *length_field = new_len_field.clone();
                            }
                        }
                    });
                    s.pop_layer();
                    rebuild_main_view(s);
                })
                .button("取消", |s| {
                    s.pop_layer();
                });

            siv.add_layer(dialog);
        }
        _ => {
            siv.add_layer(Dialog::info("暂不支持编辑此类字段"));
        }
    }
}
